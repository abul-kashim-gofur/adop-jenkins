import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl
import hudson.model.*
import hudson.security.*
import hudson.util.Secret
import jenkins.model.*
import jenkins.security.plugins.ldap.*

/**
 * @author Mihail Ivanov <mihail.ivanov@accenture.com>
 * Sets global credentials
 * Environment variables specified in docker run command/docker compose:
 *  - CREDENTIALS_IMPERSONATE_USER
 *  - CREDENTIALS_LDAP_SERVICE_USER_ID
 *  - CREDENTIALS_LDAP_SERVICE_USER
 *  - CREDENTIALS_LDAP_SERVICE_USER_PASSWORD
 *  - CREDENTIALS_LDAP_SERVICE_DESCRIPTION
 *  - CREDENTIALS_SONAR_USER_ID
 *  - CREDENTIALS_SONAR_USER
 *  - CREDENTIALS_SONAR_USER_PASSWORD
 *  - CREDENTIALS_SONAR_USER_DESCRIPTION
 *  - CREDENTIALS_JENKINSSLAVE_KEY_ID
 *  - CREDENTIALS_JENKINSSLAVE_KEY_USERNAME
 *  - CREDENTIALS_JENKINSSLAVE_KEY_DESCRIPTION
 *  - CREDENTIALS_JENKINSSLAVE_KEY_PATH (leave blank to use ~/.ssh)
 *  - CREDENTIALS_APPUSER_KEY_ID
 *  - CREDENTIALS_APPUSER_KEY_USERNAME
 *  - CREDENTIALS_APPUSER_KEY_DESCRIPTION
 *  - CREDENTIALS_APPUSER_KEY_PATH (leave blank to use ~/.ssh)
 */

// fetch Jenkins state
def env = System.getenv()
def instance = Jenkins.getInstance()

Thread.start {
        // executing the following lines as admin user instead of anonymous
        ACL.impersonate(User.get(env['CREDENTIALS_IMPERSONATE_USER']).impersonate())
        println 'Executing script as user: ' + User.current()

    println '--> Configuring global credentials'
        // define credentials
        // parameters - credential_id, credential_username, credential_password, credential_description
        def ldap_service_user = new Tuple(env['CREDENTIALS_LDAP_SERVICE_USER_ID'], env['CREDENTIALS_LDAP_SERVICE_USER'], env['CREDENTIALS_LDAP_SERVICE_USER_PASSWORD'], env['CREDENTIALS_LDAP_SERVICE_DESCRIPTION'])
        def sonar_user = new Tuple(env['CREDENTIALS_SONAR_USER_ID'], env['CREDENTIALS_SONAR_USER'], env['CREDENTIALS_SONAR_USER_PASSWORD'], env['CREDENTIALS_SONAR_USER_DESCRIPTION'])
        def nexus_user = new Tuple(env['CREDENTIALS_NEXUS_USER_ID'], env['CREDENTIALS_NEXUS_USER'], env['CREDENTIALS_NEXUS_USER_PASSWORD'], env['CREDENTIALS_NEXUS_USER_DESCRIPTION'])

        // parameters - ssh_key_id, ssh_key_username, ssh_key_description, private_key_path
        def jenkinsslave_user = new Tuple(env['CREDENTIALS_JENKINSSLAVE_KEY_ID'], env['CREDENTIALS_JENKINSSLAVE_KEY_USERNAME'], env['CREDENTIALS_JENKINSSLAVE_KEY_DESCRIPTION'], env['CREDENTIALS_JENKINSSLAVE_KEY_PATH'])
        def appuser = new Tuple(env['CREDENTIALS_APPUSER_KEY_ID'], env['CREDENTIALS_APPUSER_KEY_USERNAME'], env['CREDENTIALS_APPUSER_KEY_DESCRIPTION'], env['CREDENTIALS_APPUSER_KEY_PATH'])

        // parameter - certificate_id, certificate_password, certificate_description, certificate_path
        def docker_cloud = new Tuple(env['CREDENTIALS_DOCKER_CLOUD_CERTIFICATE_ID'], env['CREDENTIALS_DOCKER_CLOUD_CERTIFICATE_PASSWORD'], env['CREDENTIALS_DOCKER_CLOUD_CERTIFICATE_DESCRIPTION'], env['CREDENTIALS_DOCKER_CLOUD_CERTIFICATE_PATH'])

    // define two lists with all the credentials
    user_with_password_list = [sonar_user, ldap_service_user, nexus_user]
    user_with_ssh_key_list = [jenkinsslave_user, appuser]
    certificate_list = [docker_cloud]

        // set up username + password
        user_with_password_list.each {
            user_with_password = (Tuple) it
            println "--> Registering credentials"
            def system_credentials_provider = SystemCredentialsProvider.getInstance()

			def credential_description = user_with_password.get(3)

            credentials_exist = false
            system_credentials_provider.getCredentials().each {
                credentials = (com.cloudbees.plugins.credentials.Credentials) it
                if ( credentials.getDescription() == credential_description) {
                    credentials_exist = true
                    println("Found existing credentials: " + credential_description)
                }
            }

            if(!credentials_exist) {
                def credential_scope = CredentialsScope.GLOBAL
                def credential_id = user_with_password.get(0)
                def credential_username = user_with_password.get(1)
                def credential_password = user_with_password.get(2)

                def credential_domain = com.cloudbees.plugins.credentials.domains.Domain.global()
                def credential_creds = new UsernamePasswordCredentialsImpl(credential_scope,credential_id,credential_description,credential_username,credential_password)

                system_credentials_provider.addCredentials(credential_domain,credential_creds)
                println "--> Added credentials for user: " + credential_id
            }
        }

        // set up username + private key
        user_with_ssh_key_list.each {
            user_with_ssh_key = (Tuple) it
            println "--> Registering SSH Credentials"
            def system_credentials_provider = SystemCredentialsProvider.getInstance()

            def ssh_key_description = user_with_ssh_key.get(2)

            ssh_credentials_exist = false
            system_credentials_provider.getCredentials().each {
                credentials = (com.cloudbees.plugins.credentials.Credentials) it
                if ( credentials.getDescription() == ssh_key_description) {
                    ssh_credentials_exist = true
                    println("Found existing credentials: " + ssh_key_description)
                }
            }

            if(!ssh_credentials_exist) {
                def ssh_key_scope = CredentialsScope.GLOBAL
                def ssh_key_id = user_with_ssh_key.get(0)
                def ssh_key_username = user_with_ssh_key.get(1)

                // use the keys in ~/.ssh
                def ssh_key_private_key_source = new BasicSSHUserPrivateKey.UsersPrivateKeySource()

                // otherwise use path if specified
                if (user_with_ssh_key.get(3).size() > 0) {
                        ssh_key_private_key_source = new BasicSSHUserPrivateKey.FileOnMasterPrivateKeySource(user_with_ssh_key.get(3))
                }
                def ssh_key_passphrase = null
                def ssh_key_domain = com.cloudbees.plugins.credentials.domains.Domain.global()
                def ssh_key_creds = new BasicSSHUserPrivateKey(ssh_key_scope,ssh_key_id,ssh_key_username,ssh_key_private_key_source,ssh_key_passphrase,ssh_key_description)

                system_credentials_provider.addCredentials(ssh_key_domain,ssh_key_creds)
                println "--> Added credentials for user: " + ssh_key_username
            }
        }

        // set up certificate
        certificate_list.each {
        	certificate = (Tuple) it
        	println "--> Registering Certificate Credentials"
        	def system_credentials_provider = SystemCredentialsProvider.getInstance()

        	def certificate_description = certificate.get(2)

        	certificate_exist = false
        	system_credentials_provider.getCredentials().each {
        		credentials = (com.cloudbees.plugins.credentials.Credentials) it
                if ( credentials.getDescription() == ssh_key_description) {
                	certificate_exist = true
                	println("Found existing credentials: " + certificate_description)
                }
            }

            if(!credentials_exist) {
            	def certificate_scope = CredentialsScope.GLOBAL
            	def certificate_id = certificate.get(0)
            	def certificate_password = certificate.get(1)

            	def certificate_source = null

            	if (certificate.get(3).size() > 0) {
            		certificate_source = new CertificateCredentialsImpl.FileOnMasterKeyStoreSource(certificate.get(3))
            	}
            	def certificate_domain = com.cloudbees.plugins.credentials.domains.Domain.global()
            	def certificate_creds = new CertificateCredentialsImpl(certificate_scope,certificate_id,certificate_description,certificate_password,certificate_source)

            	system_credentials_provider.addCredentials(certificate_domain,certificate_creds)
            	println "--> Added certificate: " + certificate_id
            }
        }

	println '--> Finished global credentials configuration'

    // Save the state
    instance.save()

    println '--> Exiting set_credentials.groovy script'
}
