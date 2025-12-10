require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const port = process.env.PORT || 3000;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// middleware
app.use(
  cors({
    origin: process.env.CLIENT_DOMAIN,
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];

  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    console.log(decoded);
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db("foodDB");
    const mealsCollection = db.collection("meals");
    const ordersCollection = db.collection("orders");
    const usersCollection = db.collection("users");
    const chefRequestsCollection = db.collection("chefRequests");
     const roleRequestsCollection =db.collection("roleRequests")
    const reviewsCollection = db.collection("reviews");

    // role middlewares
    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "admin")
        return res
          .status(403)
          .send({ message: "Admin only Actions!", role: user?.role });

      next();
    };
    const verifyChef = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "chef")
        return res
          .status(403)
          .send({ message: "Chef only Actions!", role: user?.role });

      next();
    };

    // Save a plant data in db
    // Generate new mealId (M001, M002, M003...)
    const generateMealId = async () => {
      const lastMeal = await mealsCollection
        .find({})
        .sort({ mealId: -1 })
        .limit(1)
        .toArray();

      if (!lastMeal.length) return "M001";

      const lastIdNum = parseInt(lastMeal[0].mealId.replace("M", ""));
      const nextId = (lastIdNum + 1).toString().padStart(3, "0");

      return `M${nextId}`;
    };

    app.post("/meals", verifyJWT, verifyChef, async (req, res) => {
      try {
        const mealData = req.body;

    
        mealData.mealId = await generateMealId();

        mealData.createdAt = new Date().toISOString();

        const result = await mealsCollection.insertOne(mealData);

        res.send({ success: true, meal: mealData });
      } catch (err) {
        console.error(err);
        res.status(500).send({ success: false, message: "Failed to add meal" });
      }
    });

    // get all plants from db
    app.get("/meals", async (req, res) => {
      const result = await mealsCollection.find().toArray();
      res.send(result);
    });

    // get all plants from db
    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const result = await mealsCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Payment endpoints
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      console.log(paymentInfo);
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: paymentInfo?.name,
                description: paymentInfo?.description,
                images: [paymentInfo.image],
              },
              unit_amount: paymentInfo?.price * 100,
            },
            quantity: paymentInfo?.quantity,
          },
        ],
        customer_email: paymentInfo?.customer?.email,
        mode: "payment",
        metadata: {
          plantId: paymentInfo?.plantId,
          customer: paymentInfo?.customer.email,
        },
        success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/plant/${paymentInfo?.plantId}`,
      });
      res.send({ url: session.url });
    });

    app.post("/payment-success", async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const plant = await plantsCollection.findOne({
        _id: new ObjectId(session.metadata.plantId),
      });
      const order = await ordersCollection.findOne({
        transactionId: session.payment_intent,
      });

      if (session.status === "complete" && plant && !order) {
        // save order data in db
        const orderInfo = {
          plantId: session.metadata.plantId,
          transactionId: session.payment_intent,
          customer: session.metadata.customer,
          status: "pending",
          seller: plant.seller,
          name: plant.name,
          category: plant.category,
          quantity: 1,
          price: session.amount_total / 100,
          image: plant?.image,
        };
        const result = await ordersCollection.insertOne(orderInfo);
        // update plant quantity
        await plantsCollection.updateOne(
          {
            _id: new ObjectId(session.metadata.plantId),
          },
          { $inc: { quantity: -1 } }
        );

        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
        });
      }
      res.send(
        res.send({
          transactionId: session.payment_intent,
          orderId: order._id,
        })
      );
    });

    // get all orders for a customer by email
    app.get("/my-orders", verifyJWT, async (req, res) => {
      const result = await ordersCollection
        .find({ customer: req.tokenEmail })
        .toArray();
      res.send(result);
    });

    // get all orders for a seller by email
    app.get(
      "/manage-orders/:email",
      verifyJWT,
      verifyChef,
      async (req, res) => {
        const email = req.params.email;

        const result = await ordersCollection
          .find({ "seller.email": email })
          .toArray();
        res.send(result);
      }
    );

    // get all plants for a seller by email
    app.get("/my-inventory/:email", verifyJWT, verifyChef, async (req, res) => {
      const email = req.params.email;

      const result = await mealsCollection
        .find({ "seller.email": email })
        .toArray();
      res.send(result);
    });

    // save or update a user in db
    app.post("/user", async (req, res) => {
      try {
        const userData = req.body;
        console.log("Received user data:", userData); // Log incoming data

        userData.created_at = new Date().toISOString();
        userData.last_loggedIn = new Date().toISOString();
        if (!userData.role) {
          userData.role = "customer";
        }

        const query = {
          email: userData.email,
        };

        const alreadyExists = await usersCollection.findOne(query);
        console.log("User Already Exists---> ", !!alreadyExists);

        if (alreadyExists) {
          console.log("Updating user info......");
          const result = await usersCollection.updateOne(query, {
            $set: {
              last_loggedIn: new Date().toISOString(),
            },
          });
          return res.send(result);
        }

        console.log("Saving new user info......");
        const result = await usersCollection.insertOne(userData);
        console.log("User saved result:", result); // Log the result of insertion
        res.send(result);
      } catch (error) {
        console.error("Error in /user endpoint:", error);
        res
          .status(500)
          .send({ message: "Internal Server Error", error: error.message });
      }
    });

    // get a user's role
    app.get("/user/role", verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role });
    });

    // save become-seller request
    app.post("/become-seller", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const alreadyExists = await chefRequestsCollection.findOne({ email });
      if (alreadyExists)
        return res
          .status(409)
          .send({ message: "Already requested, wait koro." });

      const result = await chefRequestsCollection.insertOne({ email });
      res.send(result);
    });

    // get all seller requests for admin
    app.get("/seller-requests", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await chefRequestsCollection.find().toArray();
      res.send(result);
    });
    app.post("/role-request", verifyJWT, async (req, res) => {
  const { requestType } = req.body;
  const email = req.tokenEmail;

  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(404).send({ message: "User not found" });


  const exist = await roleRequestsCollection.findOne({ userEmail: email, requestStatus: "pending" });
  if (exist) {
    return res.status(409).send({ message: "You already have a pending request" });
  }

  const requestData = {
    userName: user.name || "",
    userEmail: email,
    requestType,
    requestStatus: "pending",
    requestTime: new Date().toISOString(),
  };

  await roleRequestsCollection.insertOne(requestData);
  res.send({ success: true, message: "Request submitted", request: requestData });
});
app.get("/role-requests", verifyJWT, verifyADMIN, async (req, res) => {
  const result = await roleRequestsCollection.find().toArray();
  res.send(result);
});
app.patch("/role-requests/accept/:id", verifyJWT, verifyADMIN, async (req, res) => {
  const id = req.params.id;
  const request = await roleRequestsCollection.findOne({ _id: new ObjectId(id) });

  if (!request) return res.status(404).send({ message: "Request not found" });

  let updatedRole = request.requestType;
  let roleUpdateData = {};

  if (updatedRole === "chef") {
    const chefId = "chef-" + Math.floor(1000 + Math.random() * 9000);
    roleUpdateData = { role: "chef", chefId };
  }

  if (updatedRole === "admin") {
    roleUpdateData = { role: "admin" };
  }

  await usersCollection.updateOne(
    { email: request.userEmail },
    { $set: roleUpdateData }
  );

  await roleRequestsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { requestStatus: "approved" } }
  );

  res.send({ success: true });
});
app.patch("/role-requests/reject/:id", verifyJWT, verifyADMIN, async (req, res) => {
  const id = req.params.id;

  await roleRequestsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { requestStatus: "rejected" } }
  );

  res.send({ success: true });
});
app.patch("/make-fraud", verifyJWT, verifyADMIN, async (req, res) => {
  const { email } = req.body;

  const result = await usersCollection.updateOne(
    { email },
    { $set: { status: "fraud" } }
  );

  res.send({ message: "User marked as fraud", status: "fraud" });
});


    // review endpoints
    app.post("/reviews", verifyJWT, async (req, res) => {
      try {
        const reviewData = req.body;
        reviewData.createdAt = new Date().toISOString();
        const result = await reviewsCollection.insertOne(reviewData);
        res.send({ success: true, review: reviewData });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, message: "Failed to submit review" });
      }
    });

    app.get("/reviews/:mealId", async (req, res) => {
      const mealId = req.params.mealId;
      const result = await reviewsCollection.find({ mealId }).toArray();
      res.send(result);
    });
    // get all users for admin
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
      const adminEmail = req.tokenEmail;
      const result = await usersCollection
        .find({ email: { $ne: adminEmail } })
        .toArray();
      res.send(result);
    });

    // update a user's role
    app.patch("/update-role", verifyJWT, verifyADMIN, async (req, res) => {
      const { email, role } = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: { role } }
      );
      await chefRequestsCollection.deleteOne({ email });

      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
