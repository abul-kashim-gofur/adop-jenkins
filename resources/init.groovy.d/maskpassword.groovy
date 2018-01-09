import hudson.model.*;
import jenkins.model.*;
import hudson.security.*;
import jenkins.security.plugins.ldap.*;
import hudson.util.Secret;
import com.michelin.cio.hudson.plugins.maskpasswords.*;
import com.cloudbees.plugins.credentials.*;
//Add new variables in the global mask password
//Add new password to all global mask password

//Variables from docker-compose
def env = System.getenv()

//maskpasswordvars contains all the variables which holds the passwords and are comma seperated
def maskPasswordVars = env['JENKINS_MASK_PASSWORD_VARS']
def maskPasswordVarsList = maskPasswordVars.split(',')

println "Configuring Global Mask Password"
//Define + enable Global mask passwords plugin (this will mark the mask passwords checkbox in Manage Jenkins)
def globalVarPasswordPairs = new MaskPasswordsConfig().getInstance()
globalVarPasswordPairs.addMaskedPasswordParameterDefinition("com.cloudbees.plugins.credentials.CredentialsParameterDefinition")

//Retrieve existing password pairs currently set in Manage Jenkins
existingPasswordPairs = globalVarPasswordPairs.getGlobalVarPasswordPairs()
def currentPasswordPairs = []
for (ePasswordPair in existingPasswordPairs) {
  currentPasswordPairs += ePasswordPair.getVar() 
}

//Loop through existing password pairs and compare with new password pairs
    for(maskPasswordPair in maskPasswordVarsList){
      def listPasswordsPairsToMask
      
      if ( currentPasswordPairs.contains(maskPasswordPair) == true )
      {
        println "This password variable exists: $maskPasswordPair skipping..."
      }
      else
      {
        println "Adding this var: $maskPasswordPair"
        //Building the new password pairs to be added and adding them
        listPasswordsPairsToMask = new MaskPasswordsBuildWrapper.VarPasswordPair(maskPasswordPair, env[maskPasswordPair])
        globalVarPasswordPairs.addGlobalVarPasswordPair(listPasswordsPairsToMask)
      }
    }
	
	println '-- Finished Masking password --'
// Save the state of the mask password config
	MaskPasswordsConfig.save(globalVarPasswordPairs)