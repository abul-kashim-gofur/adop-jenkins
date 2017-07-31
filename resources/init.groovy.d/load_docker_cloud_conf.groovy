import jenkins.model.*;
import hudson.slaves.Cloud;
import com.nirima.jenkins.plugins.docker.DockerCloud;
import com.nirima.jenkins.plugins.docker.DockerCloud.DescriptorImpl;
import com.nirima.jenkins.plugins.docker.DockerTemplate;
import com.nirima.jenkins.plugins.docker.DockerTemplateBase;

/**
 * @author Mihail Ivanov <mihail.ivanov@accenture.com>
 * Loads DockerCloud configuration in Cloud section of Jenkins.
 * Allows to load one DockerCloud with one or many DockerTemplates.
 * Environment variables specified in docker run command/docker compose:
 *  - DOCKER_PLUGIN_NAME
 *  - DOCKER_PLUGIN_URL
 *  - DOCKER_PLUGIN_CREDENTIALS
 *  - DOCKER_PLUGIN_CONNECTION_TIMEOUT
 *  - DOCKER_PLUGIN_READ_TIMEOUT
 *  - DOCKER_PLUGIN_CONTAINER_CAP
 *  - DOCKER_PLUGIN_TEMPLATE_ID
 *  - DOCKER_PLUGIN_TEMPLATE_LABELS
 *  - DOCKER_PLUGIN_TEMPLATE_CREDENTIALS
 *  - DOCKER_PLUGIN_TEMPLATE_REMOTE_FS_ROOT
 *  - DOCKER_PLUGIN_TEMPLATE_EXECUTORS_NUMBER
 *  - DOCKER_PLUGIN_TEMPLATE_IDLE_TERMINATION_TIME
 *  - DOCKER_PLUGIN_TEMPLATE_SSH_LAUNCH_TIMEOUT
 */

environment_variables_list = ['DOCKER_PLUGIN_NAME', 'DOCKER_PLUGIN_URL', 'DOCKER_PLUGIN_CREDENTIALS', 'DOCKER_PLUGIN_CONNECTION_TIMEOUT', 'DOCKER_PLUGIN_READ_TIMEOUT', 'DOCKER_PLUGIN_CONTAINER_CAP', 'DOCKER_PLUGIN_TEMPLATE_ID' ,'DOCKER_PLUGIN_TEMPLATE_VOLUMES' ,'DOCKER_PLUGIN_TEMPLATE_LABELS', 'DOCKER_PLUGIN_TEMPLATE_CREDENTIALS', 'DOCKER_PLUGIN_TEMPLATE_REMOTE_FS_ROOT', 'DOCKER_PLUGIN_TEMPLATE_EXECUTORS_NUMBER', 'DOCKER_PLUGIN_TEMPLATE_IDLE_TERMINATION_TIME', 'DOCKER_PLUGIN_TEMPLATE_SSH_LAUNCH_TIMEOUT']
def environment_variables_map = [:]

// Stop executing the script if required environment variables are not specified.
// Else store the environment variable value in a map
def env = System.getenv()
environment_variables_list.each {
    def value = env["$it"]
    if (value == null) {
        // TODO(mihail): fix this to actually exit the script
        println '--> Skipping configuration of docker cloud'
        return
    } else {
        environment_variables_map.put(it,value.split(','))
    }
}

// fetch Jenkins state
def instance = Jenkins.getInstance()

Thread.start {
    sleep 10000

    println '--> Configuring DockerCloud'

    // create a list of DockerTemplates
    def docker_templates_list = []
    for (i = 0; i < environment_variables_map.get('DOCKER_PLUGIN_TEMPLATE_ID').size(); i++) {
        // constructor
        // https://docs.docker.com/engine/reference/run/#/runtime-constraints-on-resources
        def docker_template_base = new DockerTemplateBase(environment_variables_map.get('DOCKER_PLUGIN_TEMPLATE_ID')[i], '', '', '', environment_variables_map.get('DOCKER_PLUGIN_TEMPLATE_VOLUMES')[0], '', '', '', new Integer(1000), new Integer(1000), new Integer(0), '', false, false, false, '')

        def docker_template = new DockerTemplate(docker_template_base, environment_variables_map.get('DOCKER_PLUGIN_TEMPLATE_LABELS')[i], environment_variables_map.get('DOCKER_PLUGIN_TEMPLATE_REMOTE_FS_ROOT')[i], '', '')

        docker_templates_list.push(docker_template)
    }

    // create DockerCloud with all DockerTemplates
    def docker_cloud = new DockerCloud(environment_variables_map.get('DOCKER_PLUGIN_NAME')[0], docker_templates_list, environment_variables_map.get('DOCKER_PLUGIN_URL')[0], environment_variables_map.get('DOCKER_PLUGIN_CONTAINER_CAP')[0] as Integer, environment_variables_map.get('DOCKER_PLUGIN_CONNECTION_TIMEOUT')[0] as Integer, environment_variables_map.get('DOCKER_PLUGIN_READ_TIMEOUT')[0] as Integer, environment_variables_map.get('DOCKER_PLUGIN_CREDENTIALS')[0], '')

    // add DockerCloud if it does not exist
    docker_cloud_already_exists = false
    instance.clouds.each {
        if (it.name.equals(docker_cloud.name)){
            println '--> Skipping adding DockerCloud with name: ' + it.name
            docker_cloud_already_exists = true
        }
    }

    if (!docker_cloud_already_exists){
        println '--> Adding DockerCloud: ' + docker_cloud.name
        instance.clouds.add(docker_cloud)
    }
    println '--> Finished docker cloud configuration'

    // Save the state
    instance.save()

    println '--> Exiting load_docker_cloud_conf.groovy script'
}