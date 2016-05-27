#!/usr/bin/env python2.7

import argparse
import glob
import os
import subprocess
import json
import py_compile
import sys
import fnmatch
import imp

try:
    from termcolor import colored
except:
    print "Module 'termcolor' does not seem to be installed, Please install it. (pip2.7 can be used)"
    exit(1)

try:
    imp.find_module('flake8')
except:
    print "flake8 does not seem to be installed, Please install it. (pip2.7 can be used)"
    exit(1)

# pylint: disable=E1601


def _get_exclude_cmds(app_dir):

    excludes = ["*.swp", "exclude_files.txt"]

    exclude_file_path = '{0}/exclude_files.txt'.format(app_dir)

    if (os.path.isfile(exclude_file_path)):
        with open(exclude_file_path, 'r') as f:
            excludes.extend([x.strip() for x in f.readlines()])

    exclude_cmd = ' '.join(['--exclude="{}"'.format(x) for x in excludes])
    # print "Exclude command: '{0}'".format(exclude_cmd)

    return exclude_cmd


def _create_app_tarball(app_dir):

    print colored("Creating tarball...", 'cyan')
    os.chdir('../')
    filename = "{0}.tgz".format(app_dir)
    exclude_cmds = _get_exclude_cmds(app_dir)
    ret_val = os.system('tar {0} -zcf {1} {2}'.format(exclude_cmds, filename, app_dir))

    if (ret_val):
        print colored("Failed...", 'red')
        exit(1)

    print colored("../{0}".format(filename), 'cyan')
    os.chdir('./{0}'.format(app_dir))
    return True


def _compile_py_files(py_files, exclude_flake):

    error_files = 0
    for py_file in py_files:
        errored_file = False
        print "Compiling: {0}".format(py_file)

        if (not exclude_flake):
            command = ['flake8', py_file]
            p = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            sout, serr = p.communicate()

            if (sout):
                errored_file = True
                print colored(sout, 'red')
                if (not args.continue_on_error):
                    print colored("Exiting...", 'cyan')
                    exit(1)
            if (serr):
                print serr

        if (errored_file):
            error_files += 1
        else:
            py_compile.compile(py_file)

    return error_files


def _install_app(app_tarball):

    sys.path.append('/opt/phantom/www/phantom_ui')

    import import_app as importer

    try:
        importer.main(app_tarball, True)
    except Exception as e:
        return False, e.message

    return True, "App Installed"

if __name__ == '__main__':

    args = None

    argparser = argparse.ArgumentParser()
    argparser.add_argument('-a', '--app_dir', help='app directory that contains all the code and json file, default is "./"', default='./')
    argparser.add_argument('-c', '--copy_py_files', help='copy py files also to the app install directory, by default on pyc files are copied', action='store_true', default=False)
    argparser.add_argument('-d', '--exclude_flake', help='Dont run flake', action='store_true', default=False)
    argparser.add_argument('-e', '--continue_on_error', help='continue even if an error is encountered while compiling a file', action='store_true', default=False)
    argparser.add_argument('-g', '--ignore_file', help='files that contains the list of files to ignore, by default it is .compile_app.ignore', default='./.compile_app.ignore')
    argparser.add_argument('-i', '--install_app', help='install app after compilation is done, by default only files are copied', action='store_true', default=False)
    argparser.add_argument('-j', '--app_json', help='App json to use, use this flag if the json filename is different from the default format of <app_dir>.json')
    argparser.add_argument('-s', '--single_pyfile', help='Compile a Single python file and exit')
    argparser.add_argument('-t', '--create_tarball', help='Only create the app tarball and exit, no compilation of py files is done', action='store_true', default=False)
    args = argparser.parse_args()

    # CD into the app directory, everything happens in relation to that
    curr_dir = os.getcwd()
    print colored("cd'ing into {0}".format(args.app_dir), 'cyan')
    os.chdir(args.app_dir)

    app_dir = os.path.split(os.getcwd())[1]

    # If only a tarball is to be created, do that and exit
    if (args.create_tarball):
        _create_app_tarball(app_dir)
        print colored("Done...", 'cyan')
        exit(0)

    # This is the directory in the apps folder that the app files will be installed
    dest_dir = "/opt/phantom/apps/{0}_app/".format(app_dir)

    error_files = 0

    # If only a single file from this directory is to be compiled, then do that and exit
    if (args.single_pyfile):
        py_files = glob.glob(args.single_pyfile)
        error_files += _compile_py_files(py_files, args.exclude_flake)
        # ignore everything else
        exit(0)

    # Handle ignore file, make a list of files that are to be ignored
    ignore_fnames = []

    if (args.ignore_file):
        if (os.path.isfile(args.ignore_file)):
            with open(args.ignore_file) as f:
                ignore_fnames = f.readlines()
                # clean up the list a bit
                ignore_fnames = [x.strip() for x in ignore_fnames if len(x.strip()) > 0]
                if (ignore_fnames):
                    print colored('Will be ignoring: {0}'.format(', '.join(ignore_fnames)), 'cyan')

    # Now search for all the py files in the app directory
    py_files = glob.glob("./*.py")
    if (ignore_fnames):
        # remove the files that we are supposed to ignore
        py_files = [x for x in py_files if not [y for y in ignore_fnames if fnmatch.fnmatch(x, y)]]

    # Compile the files
    error_files = _compile_py_files(py_files, args.exclude_flake)

    json_file = "./{0}.json".format(app_dir)

    # now work on the json file, it could have been specified on the command line
    if (args.app_json):
        json_file = args.app_json

    if (not os.path.isfile(json_file)):
        print colored('Unable to find {!r}. Exiting'.format(json_file), 'red')
        exit(1)

    # Validate the json file
    print "Validating: {0}".format(json_file)

    with open(json_file) as f:
        try:
            json.load(f)
        except Exception as e:
            print colored(str(e), 'red')
            error_files += 1
            if (not args.continue_on_error):
                print colored("Exiting...", 'cyan')
                exit(1)

    # Most of the checks are done, did we run into any errors?
    if (error_files):
        exit(1)

    # if app is required to be installed then do that and exit
    if (args.install_app):

        print colored("Installing app...", 'cyan')

        _create_app_tarball(app_dir)

        os.chdir('../')
        ret_val, err_string = _install_app("{0}.tgz".format(app_dir))

        if (not ret_val):
            print "Error: {0}".format(err_string)
            exit(1)

        os.chdir('./{0}'.format(app_dir))
        exit(0)

    # Need to copy files, instead of installation
    dest_dir = "/opt/phantom/apps/{0}_app/".format(app_dir)
    print colored("Copying pyc files to {0}".format(dest_dir), 'cyan')

    if (not os.path.isdir(dest_dir)):
        print colored("Dir {0} not found, app {1} not installed perhaps".format(dest_dir, app_dir), 'red')
        exit(1)

    # os.system("cp *.py {}".format(dest_dir))
    os.system("cp *.pyc {}".format(dest_dir))

    if (args.copy_py_files):
        print colored("Copying py files also to {0}".format(dest_dir), 'cyan')
        os.system("cp *.py {}".format(dest_dir))

    print colored("Done...", 'green')

