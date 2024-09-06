<?php
// Start the session
session_start();

// Database connection
$host = "localhost"; // Your database host
$dbUsername = "root"; // Your database username
$dbPassword = ""; // Your database password
$dbName = "hospital_db"; // Your database name

// Create connection
$conn = new mysqli($host, $dbUsername, $dbPassword, $dbName);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Retrieve input from the login form
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prevent SQL injection using prepared statements
    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    
    // Check if username exists
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($userId, $dbUsername, $dbPassword, $role);
        $stmt->fetch();
        
        // Verify password (assuming the password is hashed in the database)
        if (password_verify($password, $dbPassword)) {
            // Set session variables
            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $dbUsername;
            $_SESSION['role'] = $role;
            
            // Redirect users based on their roles
            if ($role == 'admin') {
                header('Location: admin_dashboard.php');
            } elseif ($role == 'doctor') {
                header('Location: doctor_dashboard.php');
            } elseif ($role == 'nurse') {
                header('Location: nurse_dashboard.php');
            } elseif ($role == 'patient') {
                header('Location: patient_dashboard.php');
            } else {
                echo "Invalid user role.";
            }
        } else {
            echo "Incorrect password.";
        }
    } else {
        echo "Username not found.";
    }
    
    $stmt->close();
}

$conn->close();
?>
