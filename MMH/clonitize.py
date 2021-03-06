#!/usr/bin/env python

from os import walk
from git import Repo
from git import NoSuchPathError

import os
import re
import sys
import wget
import shutil
import json
import tarfile
import requests

################################################
# Getting started notes
#
# 1) The version of "GitPython" in PyPI is too old. we have to install it from source:
#
#   git clone https://github.com/gitpython-developers/GitPython.git
#   cd GitPython && sudo python setup.py install
#
# 2) Make sure you do not have "X11Foward yes" turned on globally or in ~/.ssh/config explicitly for the git server.
#    Most of the time, X11 forwarding is not supported and will generate garbage messages that GitPython will choke on.
#
# 3) Pre-existing git repos must have been cloned using this tool, OR must have the upstream remote named "origin" configured.
#
# 4) Install other deps as needed:
#    sudo pip install --upgrade requests wget tarfile
################################################

# utility function to provide package exclusions
exclusions = [ 'origin-server', 'test-pull', 'openshift.github.com',
        'origin-dev-tools', 'rhc' ]

def exclude(url):
    for exclusion in exclusions:
        if url.find(exclusion) >= 0:
            return True
    return False

# wget progress bar function
def my_bar(current, total, fucking_useless):
    percentage = (float(current) * 100.0) / total
    sys.stdout.write("\rGrabbing " + os.path.basename(match) + ": %" + "{0:05.2f} ".format(percentage))

# tarfile creation progress function
def asshole(tarinfo):
    size = os.path.getsize(archive_file_path)
    size = size / (1024 * 1024)
    sys.stdout.write("\r" + str(size) + " MiB")
    return tarinfo

# process command line arguments
create_archive = False

if len(sys.argv) > 1:
    if sys.argv[1] == '--create-archive':
        create_archive = True

# the github organization
org = "openshift"
github_url = "https://api.github.com/orgs/" + org + "/repos"

# where we will store the cloned repos
local_storage_dir = os.path.expanduser('~') + '/github/' + org

# where we'll store centrallized local gems for export
local_gem_repo = local_storage_dir + "/gems/"

# archive file name (optional)
archive_file_path = local_storage_dir + "/" + org + ".tar.bz2"

if not os.path.exists(local_storage_dir):
    print "Creating " + local_storage_dir
    os.makedirs(local_storage_dir)

# get the list of repos for the org
print "Getting list of GitHub repositories for Organization: " + org
response = requests.get(github_url)
remote_repos = json.loads(response.content)

regex = re.compile(r'(?:wget|curl)(?:\s+)((?:https?://.*)(?:\.tar.gz|\.tgz|\.zip.*))(?:\n)')

# process each repo in the org
for remote_repo in remote_repos:

    # get the "clone" URL
    remote_repo_url = remote_repo['ssh_url']
    local_repo_storage_dir = local_storage_dir + "/" + remote_repo['name']
    local_repo_resource_storage_dir = local_storage_dir + "/" + 'resources'
    repo_title = "[" + org + " / " + remote_repo['name'] + "]"

    if exclude(remote_repo_url):
        continue

    # get the latest repo content
    try:
    # if the repo already exists, pull all updates from 'origin'
        git_repo = Repo(local_repo_storage_dir)
        print repo_title + " Repo exists. Pulling updates"
        git_repo.remotes['origin'].pull()

    except NoSuchPathError:

        # the repo doesn't exist locally; clone it!
        print repo_title + " Repo does not exist. Cloning"
        local_repo = Repo.clone_from(remote_repo_url, local_repo_storage_dir)

    print repo_title + " Looking for externally downloadable dependencies"

    if not os.path.exists(local_repo_resource_storage_dir):
        print repo_title + " Creating resources dir"
        os.makedirs(local_repo_resource_storage_dir)

    # look for remote resources that are downloaded inside scripts within the repo
    for dirpath, dirnames, filenames in walk(local_repo_storage_dir):

        for file in filenames:

            file_path = dirpath + "/" + file

            # Skip symlinks for now
            if os.path.islink(file_path) or '.git' in dirpath:
                continue

            with open(dirpath + "/" + file) as f:
                file_content = f.read()

            matches = regex.findall(file_content)

            for match in matches:
                print repo_title + " Found external resource: " + match
                os.chdir(local_repo_resource_storage_dir)
                file_name = os.path.basename(match)
                if os.path.exists(file_name):
                    os.remove(file_name)
                wget.download(match, bar=my_bar)
                #wget.download(match)
                print "" # wget doesnt print a trailing newline

            if file == 'Gemfile':
                print "Found some gems that we'll need; lets get 'em!"
                os.chdir(os.path.dirname(file_path))
                if os.path.exists('Gemfile.lock'):
                    os.remove('Gemfile.lock')
                if not os.path.exists(local_gem_repo):
                    os.mkdir(local_gem_repo)
                os.system('bundle install --path=' + local_gem_repo)
                if os.path.exists(local_repo_storage_dir + '/' + 'vendor'):
                    shutil.rmtree(local_repo_storage_dir + '/' + 'vendor')

if create_archive:
    print "Creating " + archive_file_path
    with tarfile.open(archive_file_path, "w:bz2") as tar:
        tar.add(local_storage_dir, arcname=os.path.basename(local_storage_dir), filter=asshole)
