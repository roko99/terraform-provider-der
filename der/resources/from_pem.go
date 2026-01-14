package resources

import (
	"context"
	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-der/der/utils"
)

// ResourceFromPem returns a resource that converts PEM certificates and keys to DER format
func ResourceFromPem() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFromPemCreate,
		ReadContext:   resourceFromPemRead,
		DeleteContext: resourceFromPemDelete,
		Schema: map[string]*schema.Schema{
			"cert_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "PEM-encoded certificate (or certificate chain)",
			},
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "PEM-encoded private key",
			},
			"private_key_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Default:     "",
				Description: "Password for encrypted private key",
				ForceNew:    true,
			},
			"cert_der": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Base64-encoded DER certificate",
			},
			"key_der": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Base64-encoded DER private key",
			},
			"cert_der_binary": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Raw DER certificate data",
			},
			"key_der_binary": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Raw DER private key data",
			},
		},
	}
}

func resourceFromPemCreate(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	certPEM := d.Get("cert_pem").(string)
	keyPEM := d.Get("private_key_pem").(string)
	keyPassword := d.Get("private_key_password").(string)

	// Parse the certificate
	certDER, err := utils.CertPEMToDER([]byte(certPEM))
	if err != nil {
		return diag.FromErr(err)
	}

	// Parse and convert the private key
	keyDER, err := utils.KeyPEMToDER([]byte(keyPEM), []byte(keyPassword))
	if err != nil {
		return diag.FromErr(err)
	}

	// Generate ID from the certificate
	id := utils.GenerateID(certPEM + keyPEM + keyPassword)
	d.SetId(id)

	// Set the outputs
	if err := d.Set("cert_der", base64.StdEncoding.EncodeToString(certDER)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("key_der", base64.StdEncoding.EncodeToString(keyDER)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("cert_der_binary", base64.StdEncoding.EncodeToString(certDER)); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("key_der_binary", base64.StdEncoding.EncodeToString(keyDER)); err != nil {
		return diag.FromErr(err)
	}

	return diags
}

func resourceFromPemRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// This is a computed-only resource, nothing to read from external systems
	return nil
}

func resourceFromPemDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}
