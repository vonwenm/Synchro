package synchro

import (
	"github.com/golangdaddy/go-multi-logger"
	"github.com/golangdaddy/go-tools-essential"
	"strings"
	)
	
type Deployment struct {
	ID string
	Core map[string]map[string]string
	FormDetails map[string]map[string]int
	DataResource map[string]interface{}
	Modals map[string]*Modal
	Emails map[string]*Email
	DevMode bool
	DisplayID string
	DisplayDescription string
	Title string
	DeployIP string
	DeployPort string
	Host string
	Protocol string
	SSLcert string
	SSLkey string
	AdminPort string
	AdminRoute string
	URL string
	StaticPath, UserPath, StoragePath, UploadsPath, HomePath string
	AdminContacts []string
	AdminUsers map[string]bool
	RSAKeyLength int
	MailerAPI string
	MailerDomain string
	RPCnodes map[string]map[string]string
}

func (d *Deployment) Path(p_type string) string { return "./DOMAINS/"+d.ID+"/"+p_type+"/" }

func (d *Deployment) RenderScripts(derr chan string) string {
	derr<-"**** RENDERING SCRIPTS"
	inline_scripts :=  ""
	for ii := 0; ii < 100; ii++ {
		resource := d.Core["scripts"][tools.IntToString(ii)]
		if len(resource) > 0 {
			ok, file_string := tools.URL_get(derr, d.Core["paths"]["all_static"]+resource)
			if !ok || len(file_string) < 9 { tools.Quit_slow(derr, "*Resource: FAILED TO GET URL "+resource) }
			inline_scripts += "\n\n<script>\n"+file_string+"\n</script>\n\n"		
		}
	}
	return inline_scripts
}

func extract_file(encoded_file string) string {
	ok, x := tools.Decode_base64(mlog.DummyChannel(), encoded_file)
	if ok { return string(x) }
	return ""
}

type Template struct {
	Data map[string]map[string]*Resource
	DefaultPage string
	Cache string
}

type Resource struct {
	Path string
	URL string
	Hash string
	Mime string
	Encoded string
	Cache string
}

type Email struct {
	Sender string
	Subject string
	BodyPath string
}

type Modal struct {
	Include string
	Data interface{}
}

type GeneralNetwork struct {
	Name string
	Config map[string]*Deployment
}
	
type DeploymentPackage struct {
	Hash string
	DeployCode string
	DeployData string
	DeployLibs []string
	channel chan []string
}

func (i *Infrastructure) LoadPackage(path_to_file string) {
	for {
		i.logs<-"*Deployment: LOADING DEPLOYMENT PACKAGE"
		ok, dp_file := tools.File_read_string(i.logs, path_to_file); if !ok { break }
		ok, dpackage := tools.Decode_base64(i.logs, strings.Replace(dp_file, "\n", "", -1)); if !ok { break }
		deployment := &Deployment{}
		ok = tools.Decode_json(i.logs, dpackage, deployment); if !ok { break }

		// ensure hostname is lowercase
		deployment.Host = strings.ToLower(deployment.Host)
		i.SSLCertPath = "./ssl/"+deployment.Host+"/ssl.cert"
		i.SSLKeyPath = "./ssl/"+deployment.Host+"/ssl.key"
		i.logs<-"*Deployment: LOADING SSL DATA TO DISK"
		i.Deployment = deployment
		// replace websocket urls
		socketprotocol := "ws://"; if deployment.Protocol == "https://" { socketprotocol = "wss://" }
		for _, t := range i.Templates { t.Cache = strings.Replace(t.Cache, "XXXWEBSOCKETXXX", socketprotocol+deployment.Host+":93", -1) }
		i.logs<-"*Infrastructure: DEPLOYMENT LOADED FROM DISK OK"
		return
	}
	tools.Quit_slow(i.logs, "*Infrastructure: UNABLE TO LOAD PACKAGE")
}
