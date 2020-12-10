package postgres

import (
	"context"
	"fmt"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"time"
)

const (
	defaultTimeLayout = "2006-01-02 15:04:05"
)

type Config struct {
	Username     string
	Password     string
	DatabaseName string
	Host         string
	Port         string
}

type Customer struct {
	Id           int64          `pg:",pk" json:"id"`
	FirstName    string         `pg:"first_name,notnull" json:"firstName"`
	LastName     string         `pg:"last_name,notnull" json:"lastName"`
	Email        string         `pg:"email,unique,notnull" json:"email"`
	Password     string         `pg:"password,notnull" json:"-"`
	Certificates []*Certificate `pg:"rel:has-many" json:"certificates"`
	Created      string         `pg:"created,notnull" json:"created"`
	Updated      string         `pg:"updated,notnull" json:"updated"`
	DB           *pg.DB         `pg:"-" json:"-"`
}

type Certificate struct {
	Id         int64  `pg:",pk" json:"id"`
	CustomerId int64  `pg:",notnull" json:"customerId"`
	PrivateKey string `pg:"private_key,notnull" json:"privateKey"`
	Body       string `pg:"body,notnull" json:"body"`
	Active     bool   `pg:"active,use_zero" json:"active"`
	Created    string `pg:"created,notnull" json:"created"`
	Updated    string `pg:"updated,notnull" json:"updated"`
	DB         *pg.DB `pg:"-" json:"-"`
}

func CreateService(config Config) (*pg.DB, error) {
	db := pg.Connect(&pg.Options{
		Addr:     fmt.Sprintf("%v:%v", config.Host, config.Port),
		User:     config.Username,
		Password: config.Password,
		Database: config.DatabaseName,
	})

	// generate db schema
	err := createSchema(db)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if err := db.Ping(ctx); err != nil {
		return nil, err
	}
	return db, nil
}

// createSchema creates database schema for Customer and Certificate models
func createSchema(db *pg.DB) error {
	models := []interface{}{
		(*Customer)(nil),
		(*Certificate)(nil),
	}

	for _, model := range models {
		err := db.Model(model).CreateTable(&orm.CreateTableOptions{
			//Temp:          true,
			FKConstraints: true,
			IfNotExists:   true,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Customer) Create() error {
	curTime := time.Now().Format(defaultTimeLayout)
	c.Created = curTime
	c.Updated = curTime
	_, err := c.DB.Model(c).Insert()
	return err
}

func (c *Customer) Get(certType string) error {
	var certs []*Certificate
	query := c.DB.Model(&certs).Where("customer_id = ?", c.Id)

	switch certType {
	case "active":
		query.Where("active is True")
	case "inactive":
		query.Where("active is False")
	}

	err := query.Select()
	if err != nil {
		return err
	}
	err = c.DB.Model(c).Where("id = ?", c.Id).Select()
	if err != nil {
		return err
	}
	c.Certificates = certs
	return nil
}

func (c *Customer) Update() error {
	c.Updated = time.Now().Format(defaultTimeLayout)
	_, err := c.DB.Model(c).Where("id = ?", c.Id).Update()
	return err
}

func (c *Customer) Delete() error {
	if len(c.Certificates) > 0 {
		for _, v := range c.Certificates {
			cert := v
			cert.DB = c.DB
			err := cert.Delete()
			if err != nil {
				return err
			}
		}
	}
	_, err := c.DB.Model(c).Where("id = ?", c.Id).Delete()
	return err

}

func (t *Certificate) Create() error {
	curTime := time.Now().Format(defaultTimeLayout)
	t.Created = curTime
	t.Updated = curTime
	_, err := t.DB.Model(t).Insert()
	return err
}

func (t *Certificate) Get() error {
	err := t.DB.Model(t).Where("id = ?", t.Id).Select()
	return err
}

func (t *Certificate) Update() error {
	t.Updated = time.Now().Format(defaultTimeLayout)
	_, err := t.DB.Model(t).Where("id = ?", t.Id).Update()
	return err
}

func (t *Certificate) Delete() error {
	_, err := t.DB.Model(t).Where("id = ?", t.Id).Delete()
	return err
}
