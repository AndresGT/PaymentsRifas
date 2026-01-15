package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/resend/resend-go/v2"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/paymentintent"
	"github.com/stripe/stripe-go/v84/webhook"
)

// Estructuras de datos
type PaymentRequest struct {
	RifaID  string `json:"rifaId"`
	Numeros []int  `json:"numeros"`
	UserId  string `json:"userId"`
	Email   string `json:"email"`
}

type Rifa struct {
	ID    string `json:"id"`
	Price int64  `json:"price"`
	Title string `json:"title"`
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func main() {
	godotenv.Load()
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	http.HandleFunc("/payments/create-intent", enableCORS(withCSP(CreatePaymentIntent)))
	http.HandleFunc("/payments/webhook", enableCORS(withCSP(HandleStripeWebhook)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("✅ Servidor iniciado en puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// 1. Crear el Intento de Pago (ACTUALIZADO PARA APPLE PAY)
func CreatePaymentIntent(w http.ResponseWriter, r *http.Request) {
	log.Println("--- Nuevo Intento de Pago ---")
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ Error decodificando JSON: %v", err)
		http.Error(w, "JSON inválido", 400)
		return
	}

	rifa, err := getRifa(req.RifaID)
	if err != nil {
		log.Printf("❌ Rifa %s no encontrada", req.RifaID)
		http.Error(w, "Rifa no encontrada", 404)
		return
	}

	montoTotal := (rifa.Price * int64(len(req.Numeros))) * 100

	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(montoTotal),
		Currency: stripe.String(string(stripe.CurrencyUSD)),
		// MODIFICACIÓN CLAVE: Habilitar métodos de pago automáticos para mostrar Apple Pay
		AutomaticPaymentMethods: &stripe.PaymentIntentAutomaticPaymentMethodsParams{
			Enabled: stripe.Bool(true),
		},
		Metadata: map[string]string{
			"rifa_id":    req.RifaID,
			"rifa_title": rifa.Title,
			"user_id":    req.UserId,
			"user_email": req.Email,
			"numeros":    toString(req.Numeros),
		},
	}

	pi, err := paymentintent.New(params)
	if err != nil {
		log.Printf("❌ Error Stripe API: %v", err)
		http.Error(w, "Error Stripe", 500)
		return
	}

	log.Printf("✅ Intent Creado: %s para %s", pi.ID, req.Email)
	json.NewEncoder(w).Encode(map[string]string{"clientSecret": pi.ClientSecret})
}

// 2. Webhook
func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	log.Println("--- Webhook Recibido ---")

	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ Error leyendo payload: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	signature := r.Header.Get("Stripe-Signature")

	event, err := webhook.ConstructEvent(payload, signature, endpointSecret)
	if err != nil {
		log.Printf("❌ Falló la validación del Webhook: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if event.Type == "payment_intent.succeeded" {
		var pi stripe.PaymentIntent
		err := json.Unmarshal(event.Data.Raw, &pi)
		if err != nil {
			log.Printf("❌ Error parseando PaymentIntent: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		rifaID := pi.Metadata["rifa_id"]
		rifaTitle := pi.Metadata["rifa_title"]
		userID := pi.Metadata["user_id"]
		userEmail := pi.Metadata["user_email"]
		var numeros []int
		json.Unmarshal([]byte(pi.Metadata["numeros"]), &numeros)

		if err := registrarTickets(rifaID, numeros, userID); err != nil {
			log.Printf("❌ ERROR al registrar en Supabase: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		go func() {
			if err := enviarCorreoConfirmacion(userEmail, rifaTitle, numeros); err != nil {
				log.Printf("⚠️ Error enviando correo: %v", err)
			}
		}()
	}

	w.WriteHeader(http.StatusOK)
}

// --- Middleware CSP (ACTUALIZADO PARA APPLE PAY) ---
func withCSP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' https://js.stripe.com https://m.stripe.network 'unsafe-inline'; "+
				"style-src 'self' https://js.stripe.com 'unsafe-inline'; "+
				// Se agregan dominios de Apple para frames
				"frame-src https://js.stripe.com https://m.stripe.network https://applepay.apple.com; "+
				// Se agregan gateways de Apple para la conexión
				"connect-src 'self' https://api.stripe.com https://m.stripe.network https://apple-pay-gateway.apple.com;")

		next.ServeHTTP(w, r)
	}
}

// --- Funciones de Soporte (Sin cambios necesarios) ---

func enviarCorreoConfirmacion(destinatario string, rifaNombre string, numeros []int) error {
	client := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	numsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(numeros)), ", "), "[]")

	html := fmt.Sprintf(`
		<div style="font-family: sans-serif; max-width: 500px; margin: auto; padding: 25px; border-radius: 20px; border: 1px solid #eee;">
			<h2 style="color: #ff5252;">¡Compra Exitosa!</h2>
			<p>Tus números para <b>%s</b>:</p>
			<h1 style="background: #000; color: #fff; padding: 10px; text-align: center;"># %s</h1>
		</div>`, rifaNombre, numsStr)

	params := &resend.SendEmailRequest{
		From:    "Twins Rifas <onboarding@resend.dev>",
		To:      []string{destinatario},
		Subject: "Tus números confirmados",
		Html:    html,
	}

	_, err := client.Emails.Send(params)
	return err
}

func getRifa(id string) (*Rifa, error) {
	url := fmt.Sprintf("%s/rest/v1/rifa?id=eq.%s&select=id,price,title", os.Getenv("SUPABASE_URL"), id)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("apikey", os.Getenv("SUPABASE_SERVICE_ROLE"))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_SERVICE_ROLE"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil, errors.New("error supabase")
	}
	defer resp.Body.Close()

	var data []Rifa
	json.NewDecoder(resp.Body).Decode(&data)
	if len(data) == 0 {
		return nil, errors.New("404")
	}
	return &data[0], nil
}

func registrarTickets(rifaID string, numeros []int, userID string) error {
	endpoint := fmt.Sprintf("%s/rest/v1/tikect", os.Getenv("SUPABASE_URL"))
	var payload []map[string]interface{}
	for _, n := range numeros {
		payload = append(payload, map[string]interface{}{
			"rifa_id":    rifaID,
			"number":     n,
			"profile_id": userID,
		})
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	req.Header.Set("apikey", os.Getenv("SUPABASE_SERVICE_ROLE"))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_SERVICE_ROLE"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func toString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}