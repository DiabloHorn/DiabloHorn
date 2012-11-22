#CredentialScavenger - credsca
#DiabloHorn http://diablohorn.wordpress.com
#non threaded on purpose
import ConfigParser
import imp

def parseconfig(configfile):
    """Parses and filters the configuration, returns a dictionary."""
    co = dict()
    config = ConfigParser.ConfigParser()
    config.read(configfile)
    for s in config.sections():
        #Only include modules that are marked active in the config
        if config.getboolean(s, 'active'):
            co[s] = config.items(s)
    return co

def entryparse(entry):
    """Parses the entry returning a tuple containing username,password,domain"""
    username,password = entry.strip().split(':',1)
    domain = username.split('@',1)[1].split('.',1)[0]
    return (username,password,domain)

def loadmodules(modulepath,configfile):
    """load modules & create class instances, returns a dictionary.
    
    Return dictionary is of the form: 
        <modulename>:<classinstance>
    """
    ccc = parseconfig(configfile)
    loadedmodules = dict()
    for key in ccc:
        modulefilename = key
        if not key in loadedmodules:
            #load the module based on filename
            tempmodule = imp.load_source(modulefilename, "%s%s.py" % (modulepath,modulefilename))
            #find the class
            moduleclass = getattr(tempmodule,modulefilename.title())
            #instantiate the class
            moduleinstance = moduleclass()
            loadedmodules[key] = moduleinstance
    return loadedmodules
    
def checkcreds(credentials,modules):
    """Check the given credentials against available modules.
    
    Return dictionary is of the form:
        <modulename>:[username,password,protocol]
    """
    username,password,domain = entryparse(credentials)  
    checked = dict()
    #non optimized on purpose
    for k,v in modules.iteritems():   
        res = modules[k].checklogin(username,password)     
        if res is not None:
            checked[k] = res
    if not checked:
        return None
    else:
        return checked

