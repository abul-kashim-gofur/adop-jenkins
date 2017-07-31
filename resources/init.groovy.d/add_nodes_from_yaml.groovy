#!/usr/bin/env groovy
import hudson.slaves.DumbSlave
import hudson.slaves.RetentionStrategy
import hudson.slaves.RetentionStrategy.Always
import hudson.slaves.RetentionStrategy.Demand
import hudson.slaves.ComputerLauncher
import hudson.plugins.sshslaves.SSHLauncher
import hudson.model.Node.Mode
import jenkins.model.Jenkins
// /var/lib/docker/volumes/jenkins_home/_data/war/WEB-INF/lib
import org.ho.yaml.Yaml

/**
 * @author Mihail Ivanov <mihail.ivanov@accenture.com>
 * Adds nodes to Jenkins on startup.
 * Nodes are specified in a yaml file located at /jenkins_home/nodes.yaml
 */

return

def instance = Jenkins.getInstance()

Thread.start {
    sleep 10000

	// load yaml file
	println '--> Loading yaml file from /var/jenkins_home/nodes.yaml'
	String file_content = new File('/var/jenkins_home/nodes.yaml').getText('UTF-8')
	def yaml_content = Yaml.load(file_content)

	yaml_content.each { node ->
		// fetch variables
		// DumbSlave related variables
		// http://javadoc.jenkins-ci.org/hudson/slaves/DumbSlave.html#DumbSlave(java.lang.String, java.lang.String, hudson.slaves.ComputerLauncher)
		def node_name = node.key
		def node_remote_fs_root = node.value.get('remote_fs_root')
		// SSHLauncher related variables
		// https://github.com/jenkinsci/ssh-slaves-plugin/blob/ssh-slaves-1.11/src/main/java/hudson/plugins/sshslaves/SSHLauncher.java#L268-L271
		def node_launch_method_host = node.value.get('launch_method').get('host')
		def node_launch_method_credentials = node.value.get('launch_method').get('credentials')
		def node_launch_method_port = node.value.get('launch_method').get('port')
		// Slave related variables
		// http://javadoc.jenkins-ci.org/hudson/model/Slave.html
	    def node_description = node.value.get('description')
	    def node_number_of_executors = node.value.get('number_of_exectutors')
		def node_labels = node.value.get('labels')
		def node_usage = node.value.get('usage')
		def node_retention_strategy = node.value.get('retention_strategy')

	    // debug
	    println "node_name: $node_name"
	    println "node_description: $node_description"
	    println "node_number_of_executors: $node_number_of_executors"
	    println "node_remote_fs_root: $node_remote_fs_root"
	    println "node_labels: $node_labels"
	    println "node_usage: $node_usage"
	    println "--launch method: --"
	    println "node_launch_method_host: $node_launch_method_host"
	    println "node_launch_method_credentials: $node_launch_method_credentials"
	    println "node_launch_method_port: $node_launch_method_port"
	    println "node_retention_strategy: $node_retention_strategy"
	    println "---------------"

		// create nodes
		ComputerLauncher ssh_launcher = new SSHLauncher(node_launch_method_host, node_launch_method_port as Integer, node_launch_method_credentials, '', '', '', '', new Integer(0), new Integer(0), new Integer(0))
		def dumb_slave = new DumbSlave(node_name, node_remote_fs_root, ssh_launcher)

		dumb_slave.setLabelString(node_labels)
		dumb_slave.setMode(node_usage)
		dumb_slave.setNodeDescription(node_description)
		dumb_slave.setNumExecutors(node_number_of_executors as Integer)
		if (node_retention_strategy == 'always'){
			dumb_slave.setRetentionStrategy(new RetentionStrategy.Always())
		} else if (node_retention_strategy == 'demand') {
			dumb_slave.setRetentionStrategy(new RetentionStrategy.Demand())
		}
		println '--> Adding node to jenkins'
		instance.addNode(dumb_slave)
	}
	println '--> Finished jenkins nodes configuration'

	// Save the state
	instance.save()

	println '--> Exiting add_nodes_from_yaml.groovy script'
}