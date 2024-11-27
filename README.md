# Role-Based Access Control (RBAC) System

## **Overview**

This is a Role-Based Access Control (RBAC) system built using **Node.js**, **Express.js**, and **SQLite**. The application provides secure **authentication**, **authorization**, and **role-based access control** mechanisms to manage users and their permissions effectively.

---

## **Features**

- **User Signup**: Securely register new users with hashed passwords.
- **User Login**: Authenticate users and issue JWT tokens for session management.
- **Role-Based Authorization**: Grant or restrict access to resources based on user roles (e.g., Admin, User, Manager).
- **Profile Management**:
  - View user profile.
  - Update user profile.
  - Delete user profile.
- **Protected Routes**:
  - Access resources based on role and permissions.
  - Example routes for Admin, User, and Manager access.
- **JWT Authentication**:
  - JSON Web Tokens (JWT) are used for secure session management.
- **Database Integration**:
  - SQLite database to store users, roles, and permissions.

---

## **Technologies Used**

- **Backend**: Node.js, Express.js
- **Database**: SQLite
- **Authentication**: JWT, Bcrypt
- **Error Handling**: Built-in Express middleware

---

## **Endpoints**

### **Authentication**

1. **User Signup**
   - **POST** `/sign-up`
   - **Request Body**:
     ```json
     {
       "username": "exampleUser",
       "email": "example@example.com",
       "password": "securePassword",
       "role": "Admin"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "User created successfully!"
     }
     ```

2. **User Login**
   - **POST** `/login`
   - **Request Body**:
     ```json
     {
       "email": "example@example.com",
       "password": "securePassword"
     }
     ```
   - **Response**:
     ```json
     {
       "jwtToken": "your_jwt_token",
       "role": "Admin"
     }
     ```

---

### **Protected Routes**

1. **User Profile**
   - **GET** `/profile`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "Welcome to your profile!",
       "user": {
         "id": 1,
         "role": "Admin"
       }
     }
     ```

2. **Admin Access**
   - **GET** `/admin`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "Welcome Admin!"
     }
     ```

3. **User Access**
   - **GET** `/user`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "Welcome User!"
     }
     ```

4. **Admin or Manager Access**
   - **GET** `/admin-manager`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "Welcome Admin or Manager!"
     }
     ```

---

### **Profile Management**

1. **Update Profile**
   - **PUT** `/update-profile`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Request Body**:
     ```json
     {
       "username": "newUsername",
       "email": "new@example.com",
       "password": "newPassword"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "User profile updated successfully!"
     }
     ```

2. **Delete Profile**
   - **DELETE** `/delete-profile`
   - **Headers**:
     ```json
     {
       "Authorization": "Bearer your_jwt_token"
     }
     ```
   - **Response**:
     ```json
     {
       "message": "User profile deleted successfully!"
     }
     ```

---

## **Database Schema**

### **Tables**

1. **Users**
   - `id` (Primary Key)
   - `username` (Unique)
   - `email` (Unique)
   - `password` (Hashed)
   - `RoleId` (Foreign Key)

2. **Roles**
   - `id` (Primary Key)
   - `name` (e.g., Admin, User, Manager)

---

## **Setup and Run**

### **Prerequisites**

- Node.js installed
- SQLite3 installed

### **Steps**

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/rbac-system.git
   cd rbac-system
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Initialize the database:
   - Create the `rbac-system.db` SQLite database with the `Users` and `Roles` tables.

4. Start the server:
   ```bash
   node app.js
   ```
   The server will run at `http://localhost:3000`.

---

## **Environment Variables**

Create a `.env` file to store sensitive information:
```
JWT_SECRET=your_secret_key
```

---

## **Future Enhancements**

- Password reset functionality
- Token blacklisting on logout
- Refresh tokens for long-lived sessions
- Admin dashboard for user and role management

---

## **License**

This project is licensed under the MIT License.
