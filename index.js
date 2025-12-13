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
    const paymentCollection = db.collection("payments");
    const chefRequestsCollection = db.collection("chefRequests");
    const roleRequestsCollection = db.collection("roleRequests");
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

    const generateMealId = async () => {
      const lastMeal = await mealsCollection
        .find({ mealId: { $exists: true } })
        .sort({ mealId: -1 })
        .limit(1)
        .toArray();

      if (!lastMeal.length) return "M001";

      const lastIdNum = parseInt(lastMeal[0].mealId.replace("M", ""), 10);
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

    app.get("/meals", async (req, res) => {
      const result = await mealsCollection.find().toArray();
      res.send(result);
    });

    app.get("/meals/latest", async (req, res) => {
      try {
        const result = await mealsCollection
          .find()
          .sort({ createdAt: -1 })
          .limit(10)
          .toArray();

        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch latest meals" });
      }
    });
    app.get("/meals/:id", async (req, res) => {
      const id = req.params.id;
      const result = await mealsCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post("/create-checkout-session", async (req, res) => {
      try {
        const paymentInfo = req.body;

        const price = paymentInfo.price || paymentInfo.cost;
        if (!price) {
          return res.status(400).send({ message: "Price is required" });
        }

        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: {
                  name: paymentInfo.mealName,
                  images: [paymentInfo.image],
                },
                unit_amount: Math.round(price * 100),
              },
              quantity: paymentInfo.quantity || 1,
            },
          ],
          customer_email: paymentInfo.customer?.email,

          mode: "payment",

          metadata: {
            orderId: paymentInfo.orderId,
            mealId: paymentInfo.mealId,
            customerEmail: paymentInfo.customer?.email,
            quantity: paymentInfo.quantity,
          },

          success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_DOMAIN}/meals/${paymentInfo.mealId}`,
        });

        return res.send({ url: session.url });
      } catch (error) {
        console.log("STRIPE ERROR:", error);
        return res.status(500).send({ error: error.message });
      }
    });

    app.post("/orders", async (req, res) => {
      const result = await ordersCollection.insertOne(req.body);
      res.send(result);
    });
    app.get("/my-orders", verifyJWT, async (req, res) => {
      const result = await ordersCollection
        .find({ userEmail: req.tokenEmail })
        .toArray();
      res.send(result);
    });

    app.patch("/update-order-status/:id", async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;

      const result = await ordersCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { orderStatus: status } }
      );

      res.send(result);
    });

    app.post("/payment-success", async (req, res) => {
      try {
        const { sessionId } = req.body;

        if (!sessionId) {
          return res.status(400).send({ error: "sessionId missing" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (!session.metadata || !session.metadata.mealId) {
          return res.status(400).send({ error: "mealId missing in metadata" });
        }

        const orderInfo = {
          transactionId: session.id,

          mealId: session.metadata.mealId,
          customerEmail: session.customer_email,
          amount: session.amount_total / 100,
          paymentStatus: "paid",
          paymentDate: new Date(),
        };
        const paymentResult = await paymentCollection.insertOne(orderInfo);
        const orderUpdateResult = await ordersCollection.updateOne(
          { _id: new ObjectId(session.metadata.orderId) },
          { $set: { paymentStatus: "paid" } }
        );

        return res.send({
          success: true,
          paymentInserted: paymentResult.insertedId,
          orderUpdated: orderUpdateResult.modifiedCount > 0,
        });
      } catch (error) {
        console.error("Payment Success Error:", error);
        return res.status(500).send({ error: "Internal server error" });
      }
    });

    app.get(
      "/manage-orders/:email",
      verifyJWT,
      verifyChef,
      async (req, res) => {
        try {
          const paramEmail = req.params.email;

          if (req.tokenEmail !== paramEmail) {
            return res
              .status(403)
              .send({ message: "Forbidden: email mismatch" });
          }

          const chefUser = await usersCollection.findOne({ email: paramEmail });
          if (!chefUser || !chefUser.chefId) {
            return res
              .status(404)
              .send({ message: "Chef not found or missing chefId" });
          }

          const chefId = chefUser.chefId;

          const result = await ordersCollection.find({ chefId }).toArray();
          res.send(result);
        } catch (err) {
          console.error("GET /manage-orders error:", err);
          res.status(500).send({ message: "Failed to fetch chef orders" });
        }
      }
    );

    app.get("/my-meals/:email", verifyJWT, verifyChef, async (req, res) => {
      const email = req.params.email;

      const result = await mealsCollection.find({ chefEmail: email }).toArray();
      res.send(result);
    });
    app.delete("/meals/:id", verifyJWT, verifyChef, async (req, res) => {
      const id = req.params.id;
      const result = await mealsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });
    app.put("/meals/:id", verifyJWT, verifyChef, async (req, res) => {
      const id = req.params.id;
      const updatedMeal = req.body;

      const result = await mealsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedMeal }
      );

      res.send(result);
    });

    app.post("/meals/favorite/:id", verifyJWT, async (req, res) => {
      const mealId = req.params.id;
      const { userEmail } = req.body;

      if (!userEmail)
        return res
          .status(400)
          .send({ success: false, message: "User email is required" });

      try {
        const meal = await mealsCollection.findOne({
          _id: new ObjectId(mealId),
        });
        if (!meal)
          return res
            .status(404)
            .send({ success: false, message: "Meal not found" });

        const isFavorited = meal.favorites?.includes(userEmail);

        const update = isFavorited
          ? { $pull: { favorites: userEmail } }
          : { $addToSet: { favorites: userEmail } };

        await mealsCollection.updateOne({ _id: new ObjectId(mealId) }, update);

        res.send({ success: true, favorited: !isFavorited });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, message: "Failed to toggle favorite" });
      }
    });

    app.get("/favorites", verifyJWT, async (req, res) => {
      const userEmail = req.tokenEmail;

      try {
        const favorites = await mealsCollection
          .find({ favorites: userEmail })
          .toArray();

        res.send(favorites);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch favorite meals" });
      }
    });

    app.delete("/favorites/:id", verifyJWT, async (req, res) => {
      const mealId = req.params.id;
      const userEmail = req.tokenEmail;

      try {
        await mealsCollection.updateOne(
          { _id: new ObjectId(mealId) },
          { $pull: { favorites: userEmail } }
        );

        res.send({
          success: true,
          message: "Meal removed from favorites successfully.",
        });
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, message: "Failed to remove favorite meal" });
      }
    });

    app.post("/user", async (req, res) => {
      try {
        const userData = req.body;

        userData.created_at = new Date().toISOString();
        userData.last_loggedIn = new Date().toISOString();
        if (!userData.role) {
          userData.role = "customer";
        }

        const query = {
          email: userData.email,
        };

        const alreadyExists = await usersCollection.findOne(query);

        if (alreadyExists) {
          const result = await usersCollection.updateOne(query, {
            $set: {
              last_loggedIn: new Date().toISOString(),
            },
          });
          return res.send(result);
        }

        const result = await usersCollection.insertOne(userData);

        res.send(result);
      } catch (error) {
        console.error("Error in /user endpoint:", error);
        res
          .status(500)
          .send({ message: "Internal Server Error", error: error.message });
      }
    });

    app.get("/user/role", verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role });
    });
    app.get("/user/:email", async (req, res) => {
      const email = req.params.email;
      try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found" });
        res.send(user);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.post("/become-chef", verifyJWT, async (req, res) => {
      const email = req.tokenEmail;
      const alreadyExists = await chefRequestsCollection.findOne({ email });
      if (alreadyExists)
        return res
          .status(409)
          .send({ message: "Already requested, wait koro." });

      const result = await chefRequestsCollection.insertOne({ email });
      res.send(result);
    });

    app.get("/chef-requests", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await chefRequestsCollection.find().toArray();
      res.send(result);
    });
    app.post("/role-request", verifyJWT, async (req, res) => {
      const { requestType } = req.body;
      const email = req.tokenEmail;

      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: "User not found" });

      const exist = await roleRequestsCollection.findOne({
        userEmail: email,
        requestStatus: "pending",
      });
      if (exist) {
        return res
          .status(409)
          .send({ message: "You already have a pending request" });
      }

      const requestData = {
        userName: user.name || "",
        userEmail: email,
        requestType,
        requestStatus: "pending",
        requestTime: new Date().toISOString(),
      };

      await roleRequestsCollection.insertOne(requestData);
      res.send({
        success: true,
        message: "Request submitted",
        request: requestData,
      });
    });
    app.get("/role-requests", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await roleRequestsCollection.find().toArray();
      res.send(result);
    });
    app.patch(
      "/role-requests/accept/:id",
      verifyJWT,
      verifyADMIN,
      async (req, res) => {
        const id = req.params.id;
        const request = await roleRequestsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!request)
          return res.status(404).send({ message: "Request not found" });

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
      }
    );

    app.get("/stats", verifyJWT, verifyADMIN, async (req, res) => {
      const totalPaymentAmount = await paymentCollection
        .aggregate([
          { $match: { paymentStatus: "paid" } },
          { $group: { _id: null, total: { $sum: "$amount" } } },
        ])
        .toArray();

      const totalUsers = await usersCollection.countDocuments();
      const ordersPending = await ordersCollection.countDocuments({
        orderStatus: "pending",
      });
      const ordersDelivered = await ordersCollection.countDocuments({
        orderStatus: "delivered",
      });

      res.send({
        totalPaymentAmount: totalPaymentAmount[0]?.total || 0,
        totalUsers,
        ordersPending,
        ordersDelivered,
      });
    });

    app.patch(
      "/role-requests/reject/:id",
      verifyJWT,
      verifyADMIN,
      async (req, res) => {
        const id = req.params.id;

        await roleRequestsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { requestStatus: "rejected" } }
        );

        res.send({ success: true });
      }
    );
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
    app.get("/my-reviews", verifyJWT, async (req, res) => {
      try {
        const userEmail = req.tokenEmail;
        const reviews = await reviewsCollection.find({ userEmail }).toArray();
        res.send(reviews);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Failed to fetch your reviews" });
      }
    });
    app.delete("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const reviewId = req.params.id;
        const result = await reviewsCollection.deleteOne({
          _id: new ObjectId(reviewId),
          userEmail: req.tokenEmail, // ensures only owner can delete
        });

        if (result.deletedCount === 1) {
          res.send({ success: true, message: "Review deleted successfully" });
        } else {
          res.status(404).send({ success: false, message: "Review not found" });
        }
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, message: "Failed to delete review" });
      }
    });
    app.put("/reviews/:id", verifyJWT, async (req, res) => {
      try {
        const reviewId = req.params.id;
        const { rating, comment } = req.body;

        const result = await reviewsCollection.updateOne(
          { _id: new ObjectId(reviewId), userEmail: req.tokenEmail },
          { $set: { rating, comment, updatedAt: new Date().toISOString() } }
        );

        if (result.matchedCount === 1) {
          res.send({ success: true, message: "Review updated successfully" });
        } else {
          res.status(404).send({ success: false, message: "Review not found" });
        }
      } catch (err) {
        console.error(err);
        res
          .status(500)
          .send({ success: false, message: "Failed to update review" });
      }
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

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello from Server..");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
