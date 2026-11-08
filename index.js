import express from 'express'
import { MongoClient, ObjectId } from 'mongodb'
import cors from 'cors'
import 'dotenv/config'
import { requireAuth } from './middleware/auth.js'
import debugJwtRouter from './routes/debug-jwt.js'

const app = express()
const PORT = 8000

app.use(cors())
app.use(express.json())

// TEMPORARY: remove this block and routes/debug-jwt.js before production.
if (
  process.env.NODE_ENV !== 'production' &&
  process.env.ENABLE_JWT_DEBUG === 'true'
) {
  app.use('/debug', debugJwtRouter)
  console.log('[debug-jwt] TEMPORARY endpoint enabled: GET /debug/jwt')
}

const client = new MongoClient(process.env.MONGODB_URI)

export async function connectToMongoDB() {
  try {
    await client.connect()
    console.log('You successfully connected to MongoDB!')
    return client
  } catch (err) {
    console.error('MongoDB connection failed:', err?.message ?? err)
    return null
  }
}

const mongoClient = await connectToMongoDB()

if (!mongoClient) {
  console.error('Cannot start the server without a MongoDB connection.')
  process.exit(1)
}

// Keep the existing database/collection so current data and the frontend work. 
const db = mongoClient.db('wansderlust')
const destinations = db.collection('directions')
const bookings = db.collection('bookings')

function parseObjectId(id, res) {
  if (!ObjectId.isValid(id)) {
    res.status(400).json({ error: 'Invalid id' })
    return null
  }

  return new ObjectId(id)
}

function bookingFilter(email) {
  return { $or: [{ userEmail: email }, { email }] }
}

// ---------- Destinations ----------

app.get(['/destination', '/destinations'], async (req, res) => {
  const result = await destinations.find({}).toArray()
  res.send(result)
})

app.get('/featured-destinations', async (req, res) => {
  const result = await destinations.find({}).limit(5).toArray()
  res.send(result)
})

app.get('/destination/:id', requireAuth, async (req, res) => {
  const id = parseObjectId(req.params.id, res)
  if (!id) return

  const result = await destinations.findOne({ _id: id })
  res.send({ result })
})

app.post('/add-destination', requireAuth, async (req, res) => {
  const result = await destinations.insertOne(req.body)
  res.status(201).send(result)
})

async function updateDestination(req, res) {
  const id = parseObjectId(req.params.id, res)
  if (!id) return

  const { _id, ...data } = req.body
  const result = await destinations.updateOne({ _id: id }, { $set: data })
  res.json(result)
}

app.put('/destination/:id', requireAuth, updateDestination)
app.patch('/destination/:id', requireAuth, updateDestination)

app.delete('/destination/:id', requireAuth, async (req, res) => {
  const id = parseObjectId(req.params.id, res)
  if (!id) return

  const result = await destinations.deleteOne({ _id: id })
  res.json(result)
})

// ---------- Bookings ----------

app.post('/booking', requireAuth, async (req, res) => {
  try {
    // Never trust user identity fields from the request body.
    const data = {
      ...req.body,
      userId: req.auth.userId,
      userName: req.auth.name ?? req.body.userName ?? null,
      userEmail: req.auth.email ?? req.body.userEmail ?? null,
      email: req.auth.email ?? req.body.email ?? null,
    }

    const result = await bookings.insertOne(data)
    res.status(201).send(result)
  } catch (error) {
    console.error('Booking error:', error?.message ?? error)
    res.status(500).send({ error: 'Failed to save booking' })
  }
})

async function sendMyBookings(req, res) {
  const email = req.auth.email

  if (!email) {
    return res.status(400).json({ error: 'Email is required' })
  }

  const result = await bookings.find(bookingFilter(email)).toArray()
  res.send(result)
}

// Existing frontend route.
app.get('/my-booking', requireAuth, sendMyBookings)

// Newer route from the refactored API.
app.get('/my-bookings/:email', requireAuth, async (req, res) => {
  const requested = String(req.params.email ?? '').toLowerCase()
  const authenticated = String(req.auth.email ?? '').toLowerCase()

  if (!authenticated || requested !== authenticated) {
    return res.status(403).json({ error: 'Forbidden' })
  }

  return sendMyBookings(req, res)
})

async function cancelBooking(req, res) {
  const id = parseObjectId(req.params.id, res)
  if (!id) return

  const email = req.auth.email
  if (!email) {
    return res.status(400).json({ error: 'Email is required' })
  }

  const result = await bookings.deleteOne({
    _id: id,
    ...bookingFilter(email),
  })

  if (result.deletedCount === 0) {
    return res.status(404).json({ error: 'Booking not found' })
  }

  res.send(result)
}

// Existing frontend route.
app.delete('/booking/:id', requireAuth, cancelBooking)

// Newer route from the refactored API.
app.delete('/my-bookings/:id', requireAuth, cancelBooking)

// ---------- Health ----------

app.get('/', (req, res) => {
  res.send({ message: 'Server is running fine!' })
})

app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`)
})

export default app
