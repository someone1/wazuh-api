#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import cut_array, sort_array, search_array, md5, send_request
from wazuh.exception import WazuhException
from wazuh import common
from datetime import datetime
from hashlib import sha512
from time import time, mktime
from os import path, listdir, rename, utime, environ


CLUSTER_ITEMS = [
    {
        "file_name":"/etc/client.keys",
        "umask": 0o117, # Allowed Permissions rw-rw----
        "format":"plain",
        "type": "file",
        "write_mode": "atomic",
        "conditions": {
            "higher_remote_time": True,
            "different_md5": True,
            "larger_remote_size": True
        }
    },
    {
        "file_name":"/queue/agent-info",
        "umask": 0o117, # Allowed Permissions rw-rw----
        "format":"plain",
        "type": "directory",
        "write_mode": "normal",
        "conditions": {
            "higher_remote_time": True,
            "different_md5": False,
            "larger_remote_size": False
            }
    }
    # {"file_name":"/etc/ossec.conf", "format":"xml"},
]

def read_config():
    # Get api/configuration/config.js content
    try:
        with open(common.api_config_path) as api_config_file:
            lines = filter(lambda x: x.startswith('config.cluster.'), 
                           api_config_file.readlines())
        
        name_vars = map(lambda x: x.partition("=")[::2], lines)
        config_cluster = {name.strip().split('config.')[1]:
                          var.replace("\n","").replace("]","").replace("[","").\
                          replace('\"',"").replace(";","").strip()
                          for name,var in name_vars}

        if "cluster.nodes" in config_cluster.keys():
            all_nodes = config_cluster["cluster.nodes"].split(",")
            config_cluster['cluster.nodes'] = [node.strip() for node in all_nodes]
        else:
            config_cluster["cluster.nodes"] = []
            
    except Exception as e:
        raise WazuhException(3000, str(e))

    return config_cluster


def get_nodes():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # Add localhost as node
    data = [{'url':'localhost', 'node':config_cluster['cluster.node'], 
             'status':'connected', 'cluster':config_cluster['cluster.name']}]

    for url in config_cluster["cluster.nodes"]:
        req_url = '{0}{1}'.format(url, "/cluster/node")
        error, response = send_request(req_url, config_cluster["cluster.user"], 
                            config_cluster["cluster.password"], False, "json")

        if error:
            data.append({'error': response, 'status':'disconnected'})
            continue

        data.append({'url':url, 'node':response['data']['node'], 
                     'status':'connected', 'cluster':response['data']['cluster']})

    return {'items': data, 'totalItems': len(data)}


def get_node(name=None):

    data = {}
    if not name:
        config_cluster = read_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        data["node"] = config_cluster["cluster.node"]
        data["cluster"] = config_cluster["cluster.name"]

    return data


def get_files(download=None):

    file_download = download

    # Expand directory
    expanded_items = []
    for item in CLUSTER_ITEMS:
        file_path = item['file_name']
        
        if item["type"] == "file":
            new_item = dict(item)
            new_item["path"] = file_path
            expanded_items.append(new_item)
        else:
            fullpath = common.ossec_path + file_path
            for entry in listdir(fullpath):
                new_item = dict(item)
                new_item["path"] = path.join(file_path, entry)
                expanded_items.append(new_item)

    final_items = {}
    for new_item in expanded_items:
        fullpath = common.ossec_path + new_item["path"]
        if not path.isfile(fullpath):
            continue

        modification_time = str(datetime.utcfromtimestamp(int(path.getmtime(fullpath))))
        size = path.getsize(fullpath)
        md5_hash = md5(fullpath)

        file_item = {
            new_item["path"] : {
                "umask" : new_item['umask'],
                "format" : new_item['format'],
                "write_mode" : new_item['write_mode'],
                "conditions" : new_item['conditions'],

                "md5": md5_hash,
                "modification_time" : modification_time,
                "size" : size
                }
            }

        if file_download != "" and file_download == new_item["path"]:
            return file_item

        final_items.update(file_item)

    return final_items


def get_token():
    config_cluster = read_config()

    if not config_cluster:
        raise WazuhException(3000, "No config found")

    raw_key = config_cluster["cluster.key"]
    token = sha512(raw_key).hexdigest()
    return token


def _check_token(other_token):
    my_token = get_token()
    if my_token == other_token:
        return True
    else:
        return False


def _update_file(fullpath, content, umask=None, mtime=None, w_mode=None):

    # Set Timezone to epoch converter
    environ['TZ']='UTC'

    # Write
    if w_mode == "atomic":
        f_temp = '{0}.tmp.cluster'.format(fullpath)
    else:
        f_temp = '{0}'.format(fullpath)

    dest_file = open(f_temp, "w")
    dest_file.write(content)
    dest_file.close()

    # ToDo: set umask

    mtime_epoch = int(mktime(datetime.strptime(mtime, "%Y-%m-%d %H:%M:%S").timetuple()))
    utime(f_temp, (mtime_epoch, mtime_epoch)) # (atime, mtime)

    # Atomic
    if w_mode == "atomic":
        rename(f_temp, fullpath)


def sync(output_file=False, force=None):
    """
    Sync this node with others
    :return: Files synced.
    """

    discard_list = []
    sychronize_list = []
    error_list = []

    #Cluster config
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    #Get its own files status
    own_items = get_files()
    local_files = own_items.keys()

    #Get other nodes files
    nodes = config_cluster["cluster.nodes"]

    for node in nodes:
        download_list = []

        # Get remote token
        url = '{0}{1}'.format(node, "/cluster/node/token")
        error, response = send_request(url, config_cluster["cluster.user"], config_cluster["cluster.password"], False, "json")

        if error:
            error_list.append({'node': node, 'error': response})
            continue

        remote_node_token = response['data']
        if not _check_token(remote_node_token):
            error_list.append({'node': node, 'error': "Invalid cluster token"})
            continue

        # Get remote files
        url = '{0}{1}'.format(node, "/cluster/node/files")
        error, response = send_request(url, config_cluster["cluster.user"], config_cluster["cluster.password"], False, "json")

        if error:
            error_list.append({'node': node, 'error': response})
            continue

        their_items = response["data"]
        remote_files = response['data'].keys()

        # Set of files
        missing_files_locally = set(remote_files) - set(local_files)
        missing_files_remotely =  set(local_files) - set(remote_files)
        shared_files = set(local_files).intersection(remote_files)

        # Shared files
        for filename in shared_files:
            own_items[filename]["modification_time"]
            local_file_time = datetime.strptime(own_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S")
            local_file_size = own_items[filename]["size"]
            local_file = {
                "name": filename,
                "umask" : own_items[filename]['umask'],
                "write_mode" : own_items[filename]['write_mode'],
                "conditions" : own_items[filename]['conditions'],
                "md5": own_items[filename]["md5"],
                "modification_time": own_items[filename]["modification_time"],
                "size" : own_items[filename]['size']
            }

            remote_file_time = datetime.strptime(their_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S")
            remote_file_size = their_items[filename]["size"]
            remote_file = {
                "name": filename,
                "umask" : their_items[filename]['umask'],
                "write_mode" : their_items[filename]['write_mode'],
                "conditions" : their_items[filename]['conditions'],
                "md5": their_items[filename]["md5"],
                "modification_time": their_items[filename]["modification_time"],
                "size": their_items[filename]["size"]
            }


            checked_conditions = []
            conditions = {}

            if not force:
                if remote_file["conditions"]["different_md5"]:
                    checked_conditions.append("different_md5")
                    if remote_file["md5"] != local_file["md5"]:
                        conditions["different_md5"] = True
                    else:
                        conditions["different_md5"] = False

                if remote_file["conditions"]["higher_remote_time"]:
                    checked_conditions.append("higher_remote_time")
                    if remote_file_time > local_file_time:
                        conditions["higher_remote_time"] = True
                    else:
                        conditions["higher_remote_time"] = False

                if remote_file["conditions"]["larger_remote_size"]:
                    checked_conditions.append("larger_remote_size")
                    if remote_file_size > local_file_size:
                        conditions["larger_remote_size"] = True
                    else:
                        conditions["larger_remote_size"] = False
            else:
                conditions["force"] = True

            check_item = {
                "file": remote_file,
                "checked_conditions": conditions,
                "updated": False,
                "node": node
            }

            all_conds = 0
            for checked_condition in checked_conditions:
                if conditions[checked_condition]:
                    all_conds += 1
                else:
                    break

            if all_conds == len(checked_conditions):
                download_list.append(check_item)
            else:
                discard_list.append(check_item)

        # Missing files
        for filename in missing_files_locally:

            remote_file = {
                "name": filename,
                "umask" : their_items[filename]['umask'],
                "write_mode" : their_items[filename]['write_mode'],
                "conditions" : their_items[filename]['conditions'],
                "md5": their_items[filename]["md5"],
                "modification_time": their_items[filename]["modification_time"],
                "size": their_items[filename]["size"]
            }

            remote_item = {
                "file": remote_file,
                "checked_conditions": { "missing": True},
                "updated": False,
                "node": node
            }

            download_list.append(remote_item)

        # Download
        for item in download_list:
            try:
                url = '{0}{1}'.format(node, "/cluster/node/files?download="+item["file"]["name"])

                error, downloaded_file = send_request(url, config_cluster["cluster.user"], config_cluster["cluster.password"], False, "text")
                if error:
                    error_list.append({'item': item, 'reason': downloaded_file})
                    continue

                # Fix me: wazuh path + file
                try:
                    _update_file(item['file']['name'], content=downloaded_file, umask=item['file']['umask'], mtime=item['file']['modification_time'], w_mode=item['file']['write_mode'])
                except Exception as e:
                    error_list.append({'item': item, 'reason': str(e)})
                    continue

            except Exception as e:
                error_list.append({'item': item, 'reason': str(e)})
                continue


            item["updated"] = True
            sychronize_list.append(item)

    #print check_list
    final_output = {
        'discard': discard_list,
        'error': error_list,
        'updated': sychronize_list
    }

    if output_file:
        f_o = open("{0}/logs/cluster.log".format(common.ossec_path), "a+")

        f_o.write("### {0}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        try:
            for key in final_output:
                f_o.write("\n{0}:\n".format(key))
                if key != "error":
                    for final_item in final_output[key]:
                        f_o.write("\tNode: {0}\n".format(final_item['node']))
                        f_o.write("\t\tFile: {0}\n".format(final_item['file']['name']))
                        f_o.write("\t\tChecked conditions: {0}\n".format(final_item['checked_conditions']))
                else:
                    for final_item in final_output[key]:
                        f_o.write("\t{0}\n".format(final_item))
        except:
            f_o.write("\tError logging\n")

        f_o.write("\n###\n")
        f_o.close()

    return final_output
