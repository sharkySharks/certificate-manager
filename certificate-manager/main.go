package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/go-pg/pg/v10"
	"github.com/gorilla/mux"
	pgc "github.com/sharkysharks/certificate-manager/postgres"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

var (
	c  pgc.Config
	db *pg.DB
)

type Customer struct {
	Id           int64          `json:"id"`
	FirstName    string         `json:"firstName"`
	LastName     string         `json:"lastName"`
	Email        string         `json:"email"`
	Password     string         `json:"password"`
	Certificates []*Certificate `json:"certificates"`
	Created      string         `json:"created"`
	Updated      string         `json:"updated"`
	DB           *pg.DB         `json:"-"`
}

type Certificate struct {
	Id         int64              `json:"id"`
	CustomerId string             `json:"customerId"`
	Options    CertificateOptions `json:"options"`
	Active     bool               `json:"active"`
	Created    string             `json:"created"`
	Updated    string             `json:"updated"`
	DB         *pg.DB             `json:"-"`
}

func init() {
	if c == (pgc.Config{}) {
		// grab secrets and config for db from .env
		c = pgc.Config{
			Username:     os.Getenv("POSTGRES_USER"),
			Password:     os.Getenv("POSTGRES_PASSWORD"),
			DatabaseName: os.Getenv("POSTGRES_DB"),
			Port:         os.Getenv("POSTGRES_PORT"),
			Host:         os.Getenv("POSTGRES_HOST"),
		}

		// get db connection
		database, err := pgc.CreateService(c)
		if err != nil {
			log.Fatalf("Error getting DB connection: %v", err)
		}
		db = database
		log.Print("Database connected.")
	}
	//generate CA cert and private key for signing certificate requests
	if caCert == nil || caPrivKey == nil {
		log.Print("Generating CA certificate and private key")
		_, _, err := generateCertificate(certificateAuthority)
		if err != nil {
			log.Fatalf("Failed to generate the CA certificate and private key: %v", err)
		} else if caCert == nil || caPrivKey == nil {
			log.Fatalf("Failed to assign the CA certificate and private key durign generation")
		}
		log.Print("CA certificate and private key generated successfully")
	}
}

func main() {
	handleRequests()
}

func handleRequests() {
	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		return
	})

	router.HandleFunc("/customer/{customer_id}/certificate", createCertificate).Methods("POST")
	router.HandleFunc("/customer/{customer_id}/certificates", getAllCertificates).Methods("GET")
	router.HandleFunc("/customer/{customer_id}", deleteCustomer).Methods("DELETE")
	router.HandleFunc("/customer", createCustomer).Methods("POST")
	router.HandleFunc("/certificate/{cert_id}", updateCertificate).Methods("PUT")

	log.Fatal(http.ListenAndServe(":10000", router))
}

func createCustomer(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var (
		c        Customer
		customer *pgc.Customer
	)
	err := json.Unmarshal(reqBody, &c)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	hashedAndSaltedPW, err := hashAndSalt([]byte(c.Password))
	if err != nil {
		http.Error(w, "Error processing request.", http.StatusInternalServerError)
		return
	}

	customer = &pgc.Customer{
		FirstName: c.FirstName,
		LastName:  c.LastName,
		Email:     c.Email,
		Password:  hashedAndSaltedPW,
		DB:        db,
	}
	err = customer.Create()
	if err != nil {
		http.Error(w, "Error returned when saving customer. Check request data.", http.StatusBadRequest)
		return
	}

	m := map[string]string{
		"Id": string(customer.Id),
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(m)
}

func deleteCustomer(w http.ResponseWriter, r *http.Request) {
	cId := mux.Vars(r)["customer_id"]
	customerId, err := strconv.ParseInt(cId, 10, 64)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	customer := &pgc.Customer{
		Id: customerId,
		DB: db,
	}
	err = customer.Get("")
	if err != nil {
		http.Error(w, "Customer not found. Validate request data.", http.StatusNotFound)
		return
	}
	err = customer.Delete()
	if err != nil {
		http.Error(w, "Customer not found. Validate request data.", http.StatusNotFound)
		return
	}

	m := map[string]string{
		"Id": string(customer.Id),
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(m)

}

func createCertificate(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	var (
		t    Certificate
		cert *pgc.Certificate
	)
	err := json.Unmarshal(reqBody, &t)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	key := vars["customer_id"]

	customerId, err := strconv.ParseInt(key, 10, 64)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	customer := &pgc.Customer{
		Id: customerId,
		DB: db,
	}
	err = customer.Get("")
	if err != nil {
		http.Error(w, "Malformed Request. Check that the customer id is valid.", http.StatusBadRequest)
		return
	}

	certDetails := &CertificateOptions{
		Subject:        t.Options.Subject,
		ExpYearsLength: t.Options.ExpYearsLength,
		Hosts:          t.Options.Hosts,
		isCA:           false,
	}

	newCert, privateKey, err := generateCertificate(certDetails)
	if err != nil {
		http.Error(w, "Error returned when generating the certificate. Check request data.", http.StatusInternalServerError)
		return
	}

	// all certs are active when created
	cert = &pgc.Certificate{
		CustomerId: customerId,
		PrivateKey: privateKey.String(),
		Body:       newCert.String(),
		Active:     true,
		DB:         db,
	}

	err = cert.Create()
	if err != nil {
		http.Error(w, "Error returned when saving certificate. Check request data.", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(cert)
}

func updateCertificate(w http.ResponseWriter, r *http.Request) {
	var (
		active bool
		notify bool
	)
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	tId := mux.Vars(r)["cert_id"]
	a := r.Form.Get("active")
	n := r.Form.Get("notify")

	if len(a) == 0 {
		http.Error(w, "Malformed Request. Active parameter should be set to true or false.", http.StatusBadRequest)
		return
	}
	active, err = strconv.ParseBool(a)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}
	if len(n) > 0 {
		notify, err = strconv.ParseBool(n)
		if err != nil {
			http.Error(w, "Malformed Request.", http.StatusBadRequest)
			return
		}
	}

	certId, err := strconv.ParseInt(tId, 10, 64)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	cert := &pgc.Certificate{
		Id: certId,
		DB: db,
	}
	err = cert.Get()
	if err != nil {
		http.Error(w, "Certificate not found. Validate request data.", http.StatusNotFound)
		return
	}

	// only handling changes to 'active' field, all other changes are ignored
	if cert.Active != active {
		var notification string
		if notify {
			customer := &pgc.Customer{
				Id: cert.CustomerId,
				DB: db,
			}
			err := customer.Get("")
			if err != nil {
				http.Error(w, "Customer not found. Validate request data.", http.StatusNotFound)
				return
			}
			successMessage, err := sendNotification(customer, cert, active)
			if err != nil {
				http.Error(w, "External notification failed. Aborting request.", http.StatusFailedDependency)
				return
			}
			notification = successMessage
		}

		cert.Active = active

		err = cert.Update()
		if err != nil {
			http.Error(w, "Certificate not found. Validate request data.", http.StatusNotFound)
			return
		}
		m := map[string]string{
			"CertificateId": string(cert.Id),
			"CustomerId":    string(cert.CustomerId),
			"Active":        strconv.FormatBool(cert.Active),
		}
		if notification != "" {
			m["Notification"] = notification
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(m)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func getAllCertificates(w http.ResponseWriter, r *http.Request) {
	cId := mux.Vars(r)["customer_id"]
	a := r.FormValue("active")
	var active string
	switch a {
	case "true":
		active = "active"
	case "false":
		active = "inactive"
	default:
		active = ""
	}

	customerId, err := strconv.ParseInt(cId, 10, 64)
	if err != nil {
		http.Error(w, "Malformed Request.", http.StatusBadRequest)
		return
	}

	customer := &pgc.Customer{
		Id: customerId,
		DB: db,
	}
	err = customer.Get(active)
	if err != nil {
		http.Error(w, "Certificates or Customer not found. Validate request data.", http.StatusNotFound)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(customer)
}

func hashAndSalt(pwd []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePasswords(hashedPwd string, plainPwd []byte) (bool, error) {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		return false, err
	}
	return true, nil
}

func sendNotification(customer *pgc.Customer, cert *pgc.Certificate, newStatus bool) (string, error) {
	body, err := json.Marshal(map[string]string{
		"description":    "Certification Status Change Notification",
		"previousStatus": strconv.FormatBool(cert.Active),
		"newStatus":      strconv.FormatBool(newStatus),
		"owner":          fmt.Sprintf("%s, %s", customer.LastName, customer.FirstName),
		"ownerEmail":     customer.Email,
	})

	if err != nil {
		return "", err
	}

	resp, err := http.Post("https://httpbin.org/post", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	successMsg := fmt.Sprintf("Successfully sent status change notification request to %v. response: %v", "https://httpbin.org/post", resp.StatusCode)
	return successMsg, nil
}
