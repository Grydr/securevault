package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/user/encryption-web-backend/internal/auth"
	"github.com/user/encryption-web-backend/internal/database"
	"github.com/user/encryption-web-backend/internal/handlers"
	"github.com/user/encryption-web-backend/internal/storage"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secret-default-key-change-in-production-2026!"
	}

	uploadsDir := os.Getenv("UPLOADS_DIR")
	if uploadsDir == "" {
		uploadsDir = "uploads"
	}

	// Connect to Database
	db, err := database.Connect()
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer db.Close()
	log.Printf("Connected to database using driver: %s", db.Driver)

	// Initialize Storage
	store, err := storage.NewStorage(uploadsDir)
	if err != nil {
		log.Fatalf("Storage initialization failed: %v", err)
	}

	// Initialize Services & Handlers
	authService := auth.NewAuthService(jwtSecret)
	h := handlers.NewHandler(db, authService, store)

	// Setup Router
	r := chi.NewRouter()

	// Middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// CORS configuration for frontend
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://localhost:80", "*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "Content-Disposition", "X-Decryption-Time-Ns", "X-Cipher-Algorithm", "X-Integrity-Verified"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy","service":"encryption-backend"}`))
	})

	// Public Auth routes
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)

		// Protected auth routes
		r.Group(func(r chi.Router) {
			r.Use(authService.Middleware)
			r.Get("/me", h.GetMe)
		})
	})

	// Protected application routes
	r.Group(func(r chi.Router) {
		r.Use(authService.Middleware)

		// GDPR & UU PDP Personal Data routes
		r.Route("/api/personal-data", func(r chi.Router) {
			r.Post("/", h.StorePersonalData)
			r.Get("/", h.ListPersonalData)
			r.Get("/{id}/decrypt", h.DecryptPersonalData)
			r.Delete("/{id}", h.DeletePersonalData)
		})

		// File storage routes
		r.Route("/api/files", func(r chi.Router) {
			r.Post("/upload", h.UploadFile)
			r.Get("/", h.ListFiles)
			r.Get("/{id}/download", h.DownloadFile)
			r.Delete("/{id}", h.DeleteFile)
		})

		// Benchmark routes
		r.Route("/api/benchmark", func(r chi.Router) {
			r.Post("/download", h.RunBenchmark)
		})
	})

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting Encryption Web Server on %s ...", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server stopped unexpectedly: %v", err)
	}
}
