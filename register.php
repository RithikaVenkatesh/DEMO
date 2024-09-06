<?php
// Database connection
$conn = new mysqli("localhost", "root", "", "hospital_db");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $plain_password = $_POST['password'];
    
    // Hash the password
    $hashed_password = password_hash($plain_password, PASSWORD_DEFAULT);
    
    // Check if the user already exists (by username or email)
    $check_user = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $check_user->bind_param("ss", $username, $email);
    $check_user->execute();
    $check_user->store_result();
    
    if ($check_user->num_rows > 0) {
        echo "Username or email already exists.";
    } else {
        // Insert new user into the database
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, full_name, role, created_at, status) VALUES (?, ?, ?, ?, 'patient', NOW(), 'active')");
        $full_name = ""; // Set or collect full name if required
        $stmt->bind_param("ssss", $username, $email, $hashed_password, $full_name);
        
        if ($stmt->execute()) {
            echo "User registered successfully!";
            // Optionally, redirect to login page
            // header("Location: login.html");
        } else {
            echo "Error: " . $stmt->error;
        }
    }
    
    $check_user->close();
    $stmt->close();
}

$conn->close();
?>
