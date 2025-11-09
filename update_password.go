package main

import (
	"fmt"
	"log"
	
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	
	"prysm-backend/internal/models"
)

func main() {
	// Connect to database
	dsn := "host=postgres user=prysm password=prysm dbname=prysm port=5432 sslmode=require"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	
	// Hash the password
	password := "Orbit#Funk42"
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	hashedPassword := string(hashedBytes)
	
	// Update the admin user
	var user models.User
	result := db.Where("email = ?", "admin@prysm.sh").First(&user)
	if result.Error != nil {
		log.Fatalf("Failed to find user: %v", result.Error)
	}
	
	user.Password = hashedPassword
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	
	result = db.Save(&user)
	if result.Error != nil {
		log.Fatalf("Failed to update user: %v", result.Error)
	}
	
	fmt.Println("Password updated successfully!")
}