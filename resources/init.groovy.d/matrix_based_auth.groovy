import hudson.model.*
import jenkins.model.*
import hudson.security.*
import hudson.scm.*

/**
 * @author Mihail Ivanov <mihail.ivanov@accenture.com>
 * Loads matrix-based security configuration
 * Environment variables specified in docker run command/docker compose:
 *  - MATRIX_ADMIN_GROUPS
 *  - MATRIX_NON_ADMIN_GROUPS
 * https://wiki.jenkins-ci.org/display/JENKINS/Matrix-based+security
 */

def env = System.getenv()
if (env['MATRIX_ADMIN_GROUPS'] == null) {
    println '--> Admin Groups environment variables are missing => Stopping script execution.'
    return
}

// Fetch environment variables
def matrix_admin_groups = env['MATRIX_ADMIN_GROUPS']
def matrix_admin_groups_list = matrix_admin_groups.split(',')
def matrix_non_admin_groups = env['MATRIX_NON_ADMIN_GROUPS']
def matrix_non_admin_groups_list = matrix_non_admin_groups.split(',')

// fetch Jenkins state
def instance = Jenkins.getInstance()

Thread.start {
    sleep 15000

    println '--> Configuring matrix-based security'
    // https://github.com/jenkinsci/matrix-auth-plugin/blob/matrix-auth-1.2/src/main/java/hudson/security/GlobalMatrixAuthorizationStrategy.java
    def strategy = new ProjectMatrixAuthorizationStrategy()

    // Permissions - http://javadoc.jenkins.io/archive/jenkins-1.609/hudson/security/Permission.html
    println '--> Configuring Permissions for Admin Groups'
    //list of all permission
    Set<Permission> admin_groups_permissions_map = new HashSet<Permission>();
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Build'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Configure'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Connect'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Create'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Delete'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Computer.Disconnect'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.Administer'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.Read'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.ConfigureUpdateCenter'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.RunScripts'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.UploadPlugins'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Build'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Cancel'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Configure'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Create'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Delete'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Discover'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Read'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Workspace'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Item.Move'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Run.Delete'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.Run.Update'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.View.Configure'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.View.Create'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.View.Delete'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.model.View.Read'))
    admin_groups_permissions_map.add(Permission.fromId('hudson.scm.SCM.Tag'))

    for(adGroup in matrix_admin_groups_list) {
        for(permission in admin_groups_permissions_map) {
            strategy.add(permission, adGroup)
        }
    }

    println '--> Configuring Permissions for Non-Admin Groups'
    Set<Permission> non_admin_groups_permissions_map = new HashSet<Permission>();
    non_admin_groups_permissions_map.add(Permission.fromId('hudson.model.Hudson.Read'))
    non_admin_groups_permissions_map.add(Permission.fromId('hudson.model.View.Read'))

    for(nonAdGroup in matrix_non_admin_groups_list) {
        for(permission in non_admin_groups_permissions_map) {
            strategy.add(permission, nonAdGroup)
        }
    }

    // add matrix-based security
    instance.setAuthorizationStrategy(strategy)

    println '--> Finished matrix configuration'

    // Save the state
    instance.save()

    println '--> Exiting matrix_based_auth.groovy script'
}
