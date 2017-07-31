import hudson.model.*;
import jenkins.model.*;
import hudson.tools.*;
import hudson.model.JDK;
import hudson.model.JDK.DescriptorImpl;
import hudson.tools.ZipExtractionInstaller;

/**
 * @author Mihail Ivanov <mihail.ivanov@accenture.com>
 * Installs one or more JDKs from archives.
 * Environment variables specified in docker run command/docker compose:
 *  - JDK_ARCHIVES: one or more JDKs archives
 *  - JDK_SOFTWARE_SERVER: software server from which to download the archives
 *  - JDK_SOFTWARE_SERVER_DIR: directory on the software server where the archives are
 * Example:
 * JDK_ARCHIVES=jdk-8u60-linux-x64.tar.gz
 * JDK_SOFTWARE_SERVER=http://MYSOFTWARESERVER:8080
 * JDK_SOFTWARE_SERVER_DIR=Java
 * If one of the above variables is not specified this script will be ignored.
 */

// Stop executing the script if required environment variables are not specified.
def env = System.getenv()
if (env['JDK_ARCHIVES'] == null || env['JDK_SOFTWARE_SERVER'] == null || env['JDK_SOFTWARE_SERVER_DIR'] == null ) {
    println '--> Skipping installation of JDKs from archives'
    return
}

// Fetch environment variables
def jdk_archives = env['JDK_ARCHIVES']
def jdk_archives_list = jdk_archives.split(',')
def jdk_software_server = env['JDK_SOFTWARE_SERVER']
def jdk_software_server_dir = env['JDK_SOFTWARE_SERVER_DIR']
def jdk_extracted_archive_dir = env['JDK_EXTRACTED_ARCHIVE_DIR']

// fetch Jenkins state
def instance = Jenkins.getInstance()

Thread.start {
    sleep 10000

    println '--> Installing JDKs from archives'
    def jdk_descriptor_impl = new JDK.DescriptorImpl()
    def jdk_installations = jdk_descriptor_impl.getInstallations()

    jdk_archives_list.each { 
        archive = (String) it
        // create a ZipExtractionInstaller
        def url = jdk_software_server + '/' + jdk_software_server_dir + '/' + archive
	def jdk_name = strip_extension(archive)
	def version = jdk_name.substring(4,5)
	def subversion = jdk_name.substring(6,8)
	def extracted_jdk = 'jdk1.' + version + '.0_' + subversion + '/'
	def subdir = jdk_extracted_archive_dir + jdk_name + '/' + extracted_jdk
        def zip_extract_installer = new ZipExtractionInstaller('', url, subdir)
        
        // create an InstallSourceProperty from ZipExtractionInstaller
        def install_source_property = new InstallSourceProperty([zip_extract_installer])

        // create a JDK from InstallSourceProperty
        def jdk = new JDK(jdk_name,'', [install_source_property])

        // check if JDK installation exists
        jdk_inst_exists = false
        jdk_installations.each {
            installation = (JDK) it
            if ( jdk.getName() ==  installation.getName() ) {
                jdk_inst_exists = true
                println('--> Found existing installation: ' + installation.getName())
            }
        }

        if (!jdk_inst_exists) {
            jdk_installations += jdk
        }
    }

    jdk_descriptor_impl.setInstallations((JDK[]) jdk_installations)
    jdk_descriptor_impl.save()
	
	println '--> Finished JDKs installation'

    // Save the state
    instance.save()
	
	println '--> Exiting install_jdk_from_archive.groovy script'
}

// Removes extensions from the file name
String strip_extension(String file_name){
    def file_name_without_extension = file_name.minus('.tar.gz').minus('.tar.Z').minus('.tar').minus('.zip')
    return file_name_without_extension
}
