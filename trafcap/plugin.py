import sys

from optparse import OptionParser
from trafcap.trafcap import mongoSetup
from plugin_config import getPluginNames, isPluginEnabled, setPluginEnabled

actions = ["enable","disable","status"]

def getParser():
    pluginNames = ", ".join(getPluginNames())
    actionNames = "||".join(actions)
    
    usage = """usage: %%prog PLUGIN_NAME [%s]
   Where PLUGIN_NAME is one of: %s""" % (actionNames, pluginNames)

    parser = OptionParser(usage)
    return parser


if __name__ == "__main__":

    parser = getParser()
    options, args = parser.parse_args()

    try:
        pluginName = args[0]
        action = args[1]
    except:
        parser.print_help()
        sys.exit(1)
        
    pluginNames = getPluginNames()
    if pluginName not in pluginNames:
        sys.stderr.write("You must specifiy one of the plugins: %s (saw '%s')"
             % (pluginNames, pluginName))
        sys.exit(1)

    if action not in actions:
        sys.stderr.write("You must specifiy an action: %s (saw '%s')" % (",".join(actions), action))
        sys.exit(1)

    db = mongoSetup()

    if action == "enable":
        setPluginEnabled(db, pluginName, True)
    elif action == "disable":
        setPluginEnabled(db, pluginName, False)
    if action == "status":
        print(isPluginEnabled(db, pluginName))
        
    

