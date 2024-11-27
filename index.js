const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express() 
app.use(express.json())


const path = require("path")
const {open} = require("sqlite")
const sqlite3 = require("sqlite3") 


const dbPath = path.join(__dirname, "rbac-system.db")
let database = null

const initilizeDbAndServer = async () => {
    try {
        database = await open({
            filename: dbPath,
            driver: sqlite3.Database
        })

        app.listen(3000, () => {
            console.log("Server running on http://localhost:3000")
        })

    } 
    catch (error) {
        console.log(`DB Error: ${error.message}`)
        process.exit(1)
    }
}
initilizeDbAndServer() 

//Get Roles 
app.get('/roles', async (request, response) => {
    try {
        const getRoles = `
            SELECT * 
            FROM Roles
        `;
        const roles = await database.all(getRoles);
        response.status(200).json(roles);
    } 
    catch (error) {
        response.status(500).send({ error: "Error fetching roles" });
    }
}); 

// **API 1: User Signup** 
app.post('/sign-up', async (request, response) => {
    const { username, email, password, role } = request.body

    try {
        // Check if email or username already exists
        const checkUserQuery = `
            SELECT *
            FROM Users
            WHERE 
                email = ? OR username = ?;
        `;
        const existingUser = await database.get(checkUserQuery, [email, username])
        if (existingUser){
            return response.status(400).json({message: "User already exists!"})
        } 

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10) 

        // Get the role ID 
        const getRoleQuery =`
            SELECT * 
            FROM Roles
            WHERE name = ?;
         `;
        const roleData = await database.get(getRoleQuery, [role])        
        if (!roleData){
            return response.status(400).json({message: "Invalid role!"})
        }

        // Insert user into database
        const createUserQuery = `
            INSERT INTO Users (username, email, password, RoleId)
            VALUES (?, ?, ?,?);
        `;
        const usersDetails = await database.run(createUserQuery, [username, email, hashedPassword, roleData.id])
        response.status(200).json({
            message: "User created successfully!",
            usersDetails
        })

    } catch (error) {
        response.status(500).json({Error: error.message})
    }
})

// **API 2: User Login**
app.post('/login', async (request, response) => {
    const {email, password} = request.body

    try {
        //Check If User Exists
        const getUserQuery = `
            SELECT 
                Users.*,
                Roles.name AS roleName
            FROM Users
            JOIN Roles ON Users.RoleId = Roles.id
            WHERE email = ?;
        `;
        const user = await database.get(getUserQuery, [email])
        if (!user){
            return response.status(400).json({message: "Invalid user!"})
        }

        // Validate Password 
        const isPasswordMatched = await bcrypt.compare(password, user.password)
        if (!isPasswordMatched){
            return response.status(400).json({message: "Invalid password!"})
        }

        // Generate JWT token
        const payload = {
            id: user.id,
            role: user.roleName
        }
        const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN', {expiresIn: "24h"})
        response.status(200).json({jwtToken, role: user.roleName})

    } 
    catch (error) {
        response.status(500).json({Error: error.message})
    }
})

// Middleware for protected routes
const authenticateToken =   (request, response, next) => {
    const authHeader = request.headers.authorization 
    if (!authHeader){
        return response.status(400).json({ message: "Authorization header missing!" })
    }

    const jwtToken = authHeader.split(" ")[1]

    try {
        const decoded = jwt.verify(jwtToken, 'MY_SECRET_TOKEN')
        request.user = decoded
        next()
    } 
    catch (error) {
       response.status(500).json({ message: "Invalid or expired token!" }) 
    }
} 

// Middleware for Role-Based Access Control (RBAC)
const authorize = (requiredRole) => (request, response, next) => {
    if (request.user.role !== requiredRole){
        return response.status(403).json({ message: "Access denied!" })
    }
    next()
} 



// Example route accessible to all authenticated users
app.get("/profile", authenticateToken, (request, response) => {
    response.status(200).json({ 
        message: "Welcome to your profile!", 
        user: request.user 
    })
})

// Example route accessible only to Admins
app.get("/admin", authenticateToken, authorize("Admin"), (request, response) => {
    response.status(200).json({ message: "Welcome Admin!" })
})

// Example route accessible only to Users
app.get("/user", authenticateToken, authorize("User"), (request, response) => {
    response.status(200).json({ message: "Welcome User!" })
})

// Example route that requires multiple roles (Admin or Manager)
app.get("/admin-manager", authenticateToken, (request, response, next) => {
    if (request.user.role === "Admin" || request.user.role === "Manager") {
        return next()
    }
    response.status(403).json({ message: "Access denied!" })
}, (request, response) => {
    response.status(200).json({ message: "Welcome Admin or Manager!" })
})


// **API 3: Update User Profile**
app.put("/update-profile", authenticateToken, async (request, response) =>{
    const {username, email, password} = request.body 
    const userId = request.user.id // From JWT Token 

    try {
        // Check if user exists
        const getuserQuery = `
            SELECT * 
            FROM Users 
            WHERE id = ?;
        `;
        const user = await database.get(getuserQuery, [userId])
        if (!user){
            return response.status(400).json({ message: "User not found!" })
        } 

        // Hash the new password if provided
        let hashedPassword 
        if (password){
            hashedPassword = await bcrypt.hash(password, 10)
        }

        // Update the user profile
        const updateUserQuery = `
            UPDATE Users 
            SET 
                username = COALESCE(?, username),
                email = COALESCE(?, email),
                password = COALESCE(?, password)
            WHERE id = ?;
        `;
        const result = await database.run(updateUserQuery, [
            username || user.username,
            email || user.email,
            hashedPassword || user.password,
            userId,
        ])

        if (result.changes === 0) {
            return response.status(400).json({ message: "Update failed!" })
        }

        response.status(200).json({
            message: "User profile updated successfully!",
            result
        })
    } 
    catch (error) {
        response.status(500).json({ Error: error.message })
    }
}) 


// **API 4: Delete User Profile**
app.delete('/delete-profile', authenticateToken, async (request, response) => {
    const userId = request.user.id // From JWT Token 

    try {
        // Check if user exists
        const getUserQuery = `
            SELECT * 
            FROM Users
            WHERE id = ?;
        `;
        const user = await database.get(getUserQuery, [userId]);
        if (!user) {
            return response.status(400).json({ message: "User not found!" });
        }

        // Delete the user
        const deleteUserQuery = `
            DELETE FROM Users
            WHERE id = ?;
        `;
        const deletedUser = await database.run(deleteUserQuery, [userId])
        response.status(200).json({
            message: "User profile deleted successfully!",
            deletedUser
        })
    } 
    catch (error) {
        response.status(500).json({ Error: error.message })
    }
})