package postgres

import (
	"github.com/go-pg/pg/v10"
	"log"
	"os"
	"testing"
)

var (
	c  Config
	db *pg.DB
)

func TestMain(m *testing.M) {
	log.Print("Running Setup...")
	setup()

	m.Run()

	log.Print("Tearing down...")
	err := db.Close()
	if err != nil {
		log.Printf("Error closing db connection: %v", err)
	}
}

func setup() {
	c = Config{
		Username:     os.Getenv("POSTGRES_USER"),
		Password:     os.Getenv("POSTGRES_PASSWORD"),
		DatabaseName: os.Getenv("POSTGRES_DB"),
		Port:         os.Getenv("POSTGRES_PORT"),
		Host:         os.Getenv("POSTGRES_HOST"),
	}

	// get db connection
	database, err := CreateService(c)
	if err != nil {
		log.Fatalf("Error getting DB connection: %v", err)
	}
	db = database
}

func TestCustomer_Create(t *testing.T) {
	setup()
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}
	if customer.Id == 0 {
		t.Errorf("Expected customer to be saved with a unique ID, got ID: %v", customer.Id)
	}
}

func TestCertificate_Create(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks2@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	cert := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     true,
		DB:         db,
	}
	err = cert.Create()
	if err != nil {
		t.Fatalf("Failed to create Certificate: %v", err)
	}
	if cert.Id == 0 {
		t.Errorf("Expected certificate to be saved with a unique ID, got ID: %v", cert.Id)
	}
}

func TestCustomer_Get(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks3@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	// create 3 certs for the customer
	certActive := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     true,
		DB:         db,
	}
	err = certActive.Create()
	if err != nil {
		t.Fatalf("Failed to create Certificate: %v", err)
	}

	certInactive := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     false,
		DB:         db,
	}
	err = certInactive.Create()
	if err != nil {
		t.Fatalf("Failed to create inactive Certificate: %v", err)
	}
	certActive2 := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     true,
		DB:         db,
	}
	err = certActive2.Create()
	if err != nil {
		t.Fatalf("Failed to create second active Certificate: %v", err)
	}

	err = customer.Get("active")
	if err != nil {
		t.Errorf("Error getting customer: %v", err)
	}
	if len(customer.Certificates) != 2 {
		t.Errorf("Expected the certificate to be associated with the customer. Got len(customer.Certificates): %v", len(customer.Certificates))
	}
	if customer.Certificates[0].Id != certActive.Id {
		t.Errorf("Expected the customer cert id to match. Expected: %v, got; %v", certActive.Id, customer.Certificates[0].Id)
	}
	if customer.Certificates[0].Active != true {
		t.Errorf("Expected only active certs to be returned. Got %v", customer.Certificates[0].Active)
	}
	if customer.Certificates[1].Id != certActive2.Id && customer.Certificates[1].Id != certActive.Id {
		t.Errorf("Expected the customer cert id to match one of the two active ids. Expected: %v or %v, got; %v", certActive.Id, certActive2.Id, customer.Certificates[1].Id)
	}
	if customer.Certificates[1].Active != true {
		t.Errorf("Expected only active certs to be returned. Got %v", customer.Certificates[1].Active)
	}

	err = customer.Get("inactive")
	if err != nil {
		t.Errorf("Error getting customer: %v", err)
	}
	if len(customer.Certificates) != 1 {
		t.Errorf("Expected the certificate to be associated with the customer. Got len(customer.Certificates): %v", len(customer.Certificates))
	}
	if customer.Certificates[0].Id != certInactive.Id {
		t.Errorf("Expected the customer cert id to match. Expected: %v, got; %v", certInactive.Id, customer.Certificates[0].Id)
	}
	if customer.Certificates[0].Active != false {
		t.Errorf("Expected only inactive certs to be returned. Got %v", customer.Certificates[0].Active)
	}

	err = customer.Get("")
	if err != nil {
		t.Errorf("Error getting customer: %v", err)
	}
	if len(customer.Certificates) != 3 {
		t.Errorf("Expected all the certificates to be associated with the customer. Expected: %v, Got len(customer.Certificates): %v", 3, len(customer.Certificates))
	}
}

func TestCertificate_Get(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks4@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	// create 3 certs for the customer
	cert := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "bodyody",
		Active:     true,
		DB:         db,
	}
	err = cert.Create()
	if err != nil {
		t.Fatalf("Failed to create Certificate: %v", err)
	}

	newCertQuery := &Certificate{
		Id: cert.Id,
		DB: db,
	}
	err = newCertQuery.Get()
	if err != nil {
		t.Fatalf("Failed to get cert: %v", err)
	}

	if newCertQuery.Body != cert.Body {
		t.Errorf("Expected the same cert to be returned and the body to match. Expected %v. Got %v", cert.Body, newCertQuery.Body)
	}
}

func TestCustomer_Update(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks46@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	customer.FirstName = "Michelangelo"
	err = customer.Update()
	if err != nil {
		t.Fatalf("Error updating customer: %v", err)
	}

	newCustomerQuery := &Customer{
		Id: customer.Id,
		DB: db,
	}
	err = newCustomerQuery.Get("")
	if err != nil {
		t.Fatalf("Error getting customer: %v", err)
	}
	if newCustomerQuery.FirstName != "Michelangelo" {
		t.Errorf("Expected first name to be updated. Expected: %v, got %v", "Michelangelo", newCustomerQuery.FirstName)
	}
}

func TestCertificate_Update(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks47@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	// create 3 certs for the customer
	cert := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "bodyody",
		Active:     true,
		DB:         db,
	}
	err = cert.Create()
	if err != nil {
		t.Fatalf("Failed to create Certificate: %v", err)
	}

	cert.Active = false
	err = cert.Update()
	if err != nil {
		t.Fatalf("Error updating cert: %v", err)
	}
	newCertQuery := &Certificate{
		Id: cert.Id,
		DB: db,
	}
	err = newCertQuery.Get()
	if err != nil {
		t.Fatalf("Error getting cert: %v", err)
	}
	if newCertQuery.Active != false {
		t.Errorf("Expected the cert to be updated. Expected: %v, got %v", false, newCertQuery.Active)
	}
}

func TestCustomer_Delete(t *testing.T) {
	customer := &Customer{
		FirstName: "sharky",
		LastName:  "sharks",
		Email:     "sharkysharks5@gmail.com",
		Password:  "pass",
		DB:        db,
	}
	err := customer.Create()
	if err != nil {
		t.Fatalf("Failed to create Customer: %v", err)
	}

	// create 3 certs for the customer
	certActive := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     true,
		DB:         db,
	}
	err = certActive.Create()
	if err != nil {
		t.Fatalf("Failed to create Certificate: %v", err)
	}

	certInactive := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     false,
		DB:         db,
	}
	err = certInactive.Create()
	if err != nil {
		t.Fatalf("Failed to create inactive Certificate: %v", err)
	}
	certActive2 := &Certificate{
		CustomerId: customer.Id,
		PrivateKey: "private key",
		Body:       "body body body",
		Active:     true,
		DB:         db,
	}
	err = certActive2.Create()
	if err != nil {
		t.Fatalf("Failed to create second active Certificate: %v", err)
	}

	err = customer.Get("")
	if err != nil {
		t.Fatalf("Error getting customer: %v", err)
	}

	if len(customer.Certificates) != 3 {
		t.Fatalf("Error generating customer certificates. Expected %v, got %v", 3, len(customer.Certificates))
	}
	err = certActive.Delete()
	if err != nil {
		t.Fatalf("Error deleting cert: %v", err)
	}
	if err := certActive.Get(); err != pg.ErrNoRows {
		t.Errorf("Expected to receive no rows returned error from db for active cert. Expected: %v, got %v", pg.ErrNoRows, err)
	}
	err = customer.Get("")
	if err != nil {
		t.Fatalf("Error getting customer: %v", err)
	}
	if len(customer.Certificates) != 2 {
		t.Errorf("Expected one of the certs to be deleted. Expeceted: %v, got %v", 2, len(customer.Certificates))
	}
	err = customer.Delete()
	if err != nil {
		t.Fatalf("Error deleting customer: %v", err)
	}
	if err := customer.Get(""); err != pg.ErrNoRows {
		t.Errorf("Expected to receive no rows returned error from db for customer. Expected: %v, got %v", pg.ErrNoRows, err)
	}
	if err := certInactive.Get(); err != pg.ErrNoRows {
		t.Errorf("Expected to receive no rows returned error from db for inactive cert. Expected: %v, got %v", pg.ErrNoRows, err)
	}
	if err := certActive2.Get(); err != pg.ErrNoRows {
		t.Errorf("Expected to receive no rows returned error from db for second active cert. Expected: %v, got %v", pg.ErrNoRows, err)
	}
}
