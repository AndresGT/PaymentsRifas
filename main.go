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

// Middleware CORS para permitir peticiones desde tu Frontend
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
	// Carga .env solo en local, en el host se usan variables de entorno del panel
	godotenv.Load()
	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")

	http.HandleFunc("/payments/create-intent", enableCORS(CreatePaymentIntent))
	http.HandleFunc("/payments/webhook", HandleStripeWebhook)

	// Puerto dinámico para el hosting
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Servidor de Pagos listo en el puerto %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// 1. Crear el Intento de Pago (Checkout)
func CreatePaymentIntent(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", 400)
		return
	}

	rifa, err := getRifa(req.RifaID)
	if err != nil {
		http.Error(w, "Rifa no encontrada", 404)
		return
	}

	if err := validarNumeros(req.RifaID, req.Numeros); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}

	montoTotal := (rifa.Price * int64(len(req.Numeros))) * 100

	params := &stripe.PaymentIntentParams{
		Amount:   stripe.Int64(montoTotal),
		Currency: stripe.String(string(stripe.CurrencyUSD)),
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
		log.Printf("❌ Stripe Error: %v", err)
		http.Error(w, "Error Stripe", 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"clientSecret": pi.ClientSecret})
}

// 2. Procesar la confirmación (Webhook SEGURO para Producción)
func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// VERIFICACIÓN DE FIRMA: Obligatorio en el host
	endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	signature := r.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEvent(payload, signature, endpointSecret)
	
	if err != nil {
		log.Printf("⚠️ Firma inválida (webhook no autorizado): %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if event.Type == "payment_intent.succeeded" {
		var pi stripe.PaymentIntent
		json.Unmarshal(event.Data.Raw, &pi)

		rifaID := pi.Metadata["rifa_id"]
		rifaTitle := pi.Metadata["rifa_title"]
		userID := pi.Metadata["user_id"]
		userEmail := pi.Metadata["user_email"]
		var numeros []int
		json.Unmarshal([]byte(pi.Metadata["numeros"]), &numeros)

		log.Printf("💰 Pago verificado de: %s", userEmail)

		// 1. Registro en DB
		if err := registrarTickets(rifaID, numeros, userID); err != nil {
			log.Printf("❌ ERROR DB: %v", err)
			return
		}

		// 2. Correo en segundo plano
		go func() {
			if err := enviarCorreoConfirmacion(userEmail, rifaTitle, numeros); err != nil {
				log.Printf("⚠️ Error correo: %v", err)
			} else {
				log.Printf("📧 Correo enviado a %s", userEmail)
			}
		}()
	}

	w.WriteHeader(http.StatusOK)
}

// --- Soporte de Correo (Resend) ---
func enviarCorreoConfirmacion(destinatario string, rifaNombre string, numeros []int) error {
	client := resend.NewClient(os.Getenv("RESEND_API_KEY"))
	numsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(numeros)), ", "), "[]")

	html := fmt.Sprintf(`
		<div style="font-family: sans-serif; max-width: 500px; margin: auto; border: 1px solid #eee; padding: 25px; border-radius: 20px;">
			<h2 style="color: #ff5252; text-align: center;">¡Confirmación de Compra!</h2>
			<p>Hola, tus números para la rifa <strong>%s</strong> ya están registrados.</p>
			<div style="background: #111; color: #fff; padding: 20px; border-radius: 15px; text-align: center; margin: 20px 0;">
				<p style="margin: 0; font-size: 12px; color: #aaa;">TUS NÚMEROS:</p>
				<h1 style="margin: 5px 0; letter-spacing: 2px;"># %s</h1>
			</div>
			<p style="font-size: 12px; color: #777; text-align: center;">Este es un recibo automático de Twins Rifas.</p>
		</div>
	`, rifaNombre, numsStr)

	params := &resend.SendEmailRequest{
		From:    "Twins Rifas <onboarding@resend.dev>",
		To:      []string{destinatario},
		Subject: "Tus números para " + rifaNombre,
		Html:    html,
	}

	_, err := client.Emails.Send(params)
	return err
}

// --- Soporte Supabase ---
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
	if len(data) == 0 { return nil, errors.New("404") }
	return &data[0], nil
}

func validarNumeros(rifaID string, numeros []int) error {
	var nStrs []string
	for _, n := range numeros { nStrs = append(nStrs, fmt.Sprint(n)) }
	url := fmt.Sprintf("%s/rest/v1/tikect?rifa_id=eq.%s&number=in.(%s)", os.Getenv("SUPABASE_URL"), rifaID, strings.Join(nStrs, ","))

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("apikey", os.Getenv("SUPABASE_SERVICE_ROLE"))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPABASE_SERVICE_ROLE"))

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	var count []interface{}
	json.NewDecoder(resp.Body).Decode(&count)
	if len(count) > 0 { return errors.New("algunos números ya no están disponibles") }
	return nil
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
	req.Header.Set("Prefer", "return=minimal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode >= 400 { return fmt.Errorf("error registro") }
	return nil
}

func toString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}