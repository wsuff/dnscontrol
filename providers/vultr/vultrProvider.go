package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/providers"
	govultr "github.com/vultr/govultr/v3"
	"golang.org/x/net/idna"
	"golang.org/x/oauth2"
)

/*

Vultr API DNS provider:

Info required in `creds.json`:
   - token

*/

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanGetZones:            providers.Can(),
	providers.CanConcur:              providers.Unimplemented(),
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "VULTR"
	const providerMaintainer = "@pgaskin"
	fns := providers.DspFuncs{
		Initializer:   NewProvider,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// vultrProvider represents the Vultr DNSServiceProvider.
type vultrProvider struct {
	client *govultr.Client
	token  string
}

// defaultNS contains the default nameservers for Vultr.
var defaultNS = []string{
	"ns1.vultr.com",
	"ns2.vultr.com",
}

// NewProvider initializes a Vultr DNSServiceProvider.
func NewProvider(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	token := m["token"]
	if token == "" {
		return nil, errors.New("missing Vultr API token")
	}

	config := &oauth2.Config{}
	ctx := context.Background()
	ts := config.TokenSource(ctx, &oauth2.Token{AccessToken: token})
	client := govultr.NewClient(oauth2.NewClient(ctx, ts))
	client.SetUserAgent("dnscontrol")

	_, _, err := client.Account.Get(ctx)
	return &vultrProvider{client, token}, err
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (api *vultrProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	domain := dc.Name
	listOptions := &govultr.ListOptions{}
	var curRecords models.Records

	for {
		records, meta, _, err := api.client.DomainRecord.List(context.Background(), domain, listOptions)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			r, err := toRecordConfig(domain, record)
			if err != nil {
				return nil, err
			}
			curRecords = append(curRecords, r)
		}
		if meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}

	return curRecords, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (api *vultrProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, curRecords models.Records) ([]*models.Correction, int, error) {
	var corrections []*models.Correction

	for _, rec := range dc.Records {
		switch rec.Type { // #rtype_variations
		case "ALIAS", "MX", "NS", "CNAME", "PTR", "SRV", "URL", "URL301", "FRAME", "R53_ALIAS", "AKAMAICDN", "CLOUDNS_WR":
			// These rtypes are hostnames, therefore need to be converted (unlike, for example, an AAAA record)
			t, err := idna.ToUnicode(rec.GetTargetField())
			if err != nil {
				return nil, 0, err
			}
			if err := rec.SetTarget(t); err != nil {
				return nil, 0, err
			}
		default:
			// Nothing to do.
		}
	}

	changes, actualChangeCount, err := diff2.ByRecord(curRecords, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	for _, change := range changes {
		switch change.Type {
		case diff2.REPORT:
			corrections = append(corrections, &models.Correction{Msg: change.MsgsJoined})
		case diff2.CREATE:
			r := toVultrRecord(change.New[0], "0")
			priority := r.Priority
			corrections = append(corrections, &models.Correction{
				Msg: change.Msgs[0],
				F: func() error {
					_, _, err := api.client.DomainRecord.Create(context.Background(), dc.Name, &govultr.DomainRecordCreateReq{Name: r.Name, Type: r.Type, Data: r.Data, TTL: r.TTL, Priority: &priority})
					return err
				},
			})
		case diff2.CHANGE:
			r := toVultrRecord(change.New[0], change.Old[0].Original.(govultr.DomainRecord).ID)
			name := r.Name
			priority := r.Priority
			corrections = append(corrections, &models.Correction{
				Msg: fmt.Sprintf("%s; Vultr RecordID: %v", change.Msgs[0], r.ID),
				F: func() error {
					return api.client.DomainRecord.Update(context.Background(), dc.Name, r.ID, &govultr.DomainRecordUpdateReq{Name: &name, Type: r.Type, Data: r.Data, TTL: r.TTL, Priority: &priority})
				},
			})
		case diff2.DELETE:
			id := change.Old[0].Original.(govultr.DomainRecord).ID
			corrections = append(corrections, &models.Correction{
				Msg: fmt.Sprintf("%s; Vultr RecordID: %v", change.Msgs[0], id),
				F: func() error {
					return api.client.DomainRecord.Delete(context.Background(), dc.Name, id)
				},
			})
		default:
			panic(fmt.Sprintf("unhandled change.Type %s", change.Type))
		}
	}

	return corrections, actualChangeCount, nil
}

// GetNameservers gets the Vultr nameservers for a domain.
func (api *vultrProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return models.ToNameservers(defaultNS)
}

// ListZones returns the list of zones (domains) in this Vultr account.
func (api *vultrProvider) ListZones() ([]string, error) {
	var zones []string
	listOptions := &govultr.ListOptions{}
	for {
		domains, meta, _, err := api.client.Domain.List(context.Background(), listOptions)
		if err != nil {
			return nil, err
		}
		for _, d := range domains {
			zones = append(zones, d.Domain)
		}
		if meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}
	return zones, nil
}

// EnsureZoneExists creates a zone if it does not exist.
func (api *vultrProvider) EnsureZoneExists(domain string, metadata map[string]string) error {
	if ok, err := api.isDomainInAccount(domain); err != nil {
		return err
	} else if ok {
		return nil
	}

	// Vultr requires an initial IP, use a dummy one.
	_, _, err := api.client.Domain.Create(context.Background(), &govultr.DomainReq{Domain: domain, IP: "0.0.0.0", DNSSec: "disabled"})
	return err
}

func (api *vultrProvider) isDomainInAccount(domain string) (bool, error) {
	listOptions := &govultr.ListOptions{}

	for {
		domains, meta, _, err := api.client.Domain.List(context.Background(), listOptions)
		if err != nil {
			return false, err
		}

		for _, d := range domains {
			if d.Domain == domain {
				return true, nil
			}
		}

		if meta.Links.Next == "" {
			break
		}
		listOptions.Cursor = meta.Links.Next
	}
	return false, nil
}

// toRecordConfig converts a Vultr DomainRecord to a RecordConfig. #rtype_variations.
func toRecordConfig(domain string, r govultr.DomainRecord) (*models.RecordConfig, error) {
	origin, data := domain, r.Data

	rc := &models.RecordConfig{
		TTL:      uint32(r.TTL),
		Original: r,
	}
	rc.SetLabel(r.Name, domain)

	switch rtype := r.Type; rtype {
	case "ALIAS", "MX", "NS", "CNAME", "PTR", "SRV", "URL", "URL301", "FRAME", "R53_ALIAS", "AKAMAICDN", "CLOUDNS_WR":
		var err error
		data, err = idna.ToUnicode(data)
		if err != nil {
			return nil, err
		}
	default:
	}

	switch rtype := r.Type; rtype {
	case "CNAME", "NS":
		rc.Type = r.Type
		// Make target into a FQDN if it is a CNAME, NS, MX, or SRV.
		if !strings.HasSuffix(data, ".") {
			data = data + "."
		}
		return rc, rc.SetTarget(data)
	case "CAA":
		// Vultr returns CAA records in the format "[flag] [tag] [value]".
		return rc, rc.SetTargetCAAString(data)
	case "MX":
		if !strings.HasSuffix(data, ".") {
			data = data + "."
		}
		return rc, rc.SetTargetMX(uint16(r.Priority), data)
	case "SRV":
		// Vultr returns SRV records in the format "[weight] [port] [target]".
		if !strings.HasSuffix(data, ".") {
			data = data + "."
		}
		return rc, rc.SetTargetSRVPriorityString(uint16(r.Priority), data)
	case "TXT":
		// TXT records from Vultr are always surrounded by quotes.
		// They don't permit quotes within the string, therefore there is no
		// need to resolve \" or other quoting.
		if !strings.HasPrefix(data, `"`) || !strings.HasSuffix(data, `"`) {
			// Give an error if Vultr changes their protocol. We'd rather break
			// than do the wrong thing.
			return nil, errors.New("unexpected lack of quotes in TXT record from Vultr")
		}
		return rc, rc.SetTargetTXT(data[1 : len(data)-1])
	default:
		return rc, rc.PopulateFromString(rtype, r.Data, origin)
	}
}

// toVultrRecord converts a RecordConfig converted by toRecordConfig back to a Vultr DomainRecord. #rtype_variations.
func toVultrRecord(rc *models.RecordConfig, vultrID string) *govultr.DomainRecord {
	name := rc.GetLabel()
	// Vultr uses a blank string to represent the apex domain.
	if name == "@" {
		name = ""
	}

	data := rc.GetTargetField()

	// Vultr does not use a period suffix for CNAME, NS, MX or SRV.
	data = strings.TrimSuffix(data, ".")

	priority := 0

	if rc.Type == "MX" {
		priority = int(rc.MxPreference)
	}
	if rc.Type == "SRV" {
		priority = int(rc.SrvPriority)
	}

	r := &govultr.DomainRecord{
		ID:       vultrID,
		Type:     rc.Type,
		Name:     name,
		Data:     data,
		TTL:      int(rc.TTL),
		Priority: priority,
	}
	switch rtype := rc.Type; rtype { // #rtype_variations
	case "SRV":
		if data == "" {
			data = "."
		}
		r.Data = fmt.Sprintf("%v %v %s", rc.SrvWeight, rc.SrvPort, data)
	case "CAA":
		r.Data = fmt.Sprintf(`%v %s "%s"`, rc.CaaFlag, rc.CaaTag, rc.GetTargetField())
	case "SSHFP":
		r.Data = fmt.Sprintf("%d %d %s", rc.SshfpAlgorithm, rc.SshfpFingerprint, rc.GetTargetField())
	case "TXT":
		// Vultr doesn't permit TXT strings to include double-quotes
		// therefore, we don't have to escape interior double-quotes.
		// Vultr's API requires the string to begin and end with double-quotes.
		r.Data = `"` + strings.Join(rc.GetTargetTXTSegmented(), "") + `"`
	default:
	}

	return r
}
