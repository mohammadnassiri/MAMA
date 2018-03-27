import json
from decouple import config
import datetime
from django.http import HttpResponse, Http404
import os
import subprocess
from os import listdir
from os.path import isfile, join
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from api.models import Record, Vbox
import pefile
import time

from server import settings


def index(request):
    # TODO: more information provide
    return render(request, 'api/index.html')


@csrf_exempt
def request(request):
    json_response = "0"
    if request.method == "POST":
        arch = request.POST.get('arch')
        if arch == "x86":
            arch = "IMAGE_FILE_MACHINE_I386"
        if arch == "x64":
            arch = "IMAGE_FILE_MACHINE_AMD64"
        response = Record.objects.filter(status=0).filter(arch=arch).order_by('id').first()
        if response:
            output = {
                'id': response.id,
                'name': response.name,
                'arch': response.arch,
            }
            json_response = json.dumps(output)
    return HttpResponse(json_response)


@csrf_exempt
def download(request):
    if request.method == "POST":
        id = request.POST.get('id')
        vbox = request.POST.get('vbox')
        # update file and vbox models
        file = Record.objects.filter(id=id).first()
        if file:
            file.status = 1
            file.vbox = vbox
            file.save()
            # update vbox model
            vbox_model = Vbox.objects.filter(name=vbox).first()
            vbox_model.status = 1
            vbox_model.time = datetime.datetime.now()
            vbox_model.save()
            # send file
            file_path = os.path.join(file.path.name, file.name)
            if os.path.exists(file_path):
                with open(file_path, 'rb') as fh:
                    response = HttpResponse(fh.read(), content_type='application/x-download')
                    response['Content-Disposition'] = 'inline; filename=' + file.name
                    return response
        raise Http404


@csrf_exempt
def result(request):
    if request.method == "POST":
        id = request.POST.get('id')
        vbox = request.POST.get('vbox')
        file = Record.objects.filter(id=id).first()
        if file:
            file.response = request.POST.get('response')
            file.sequence = request.POST.get('sequence')
            if request.FILES.get('run_pe_file'):
                file.run_pe_file = request.FILES.get('run_pe_file')
            if request.POST.get('run_pe_sequence'):
                file.run_pe_sequence = request.POST.get('run_pe_sequence')
            if request.FILES.get('screen_shot'):
                file.screen_shot = request.FILES.get('screen_shot')
            file.run_pe = request.POST.get('run_pe')
            file.status = 2
            file.updated_time = datetime.datetime.now()
            # move file to traced folder
            new_path = os.path.join(file.path.name, "traced")
            os.rename(os.path.join(file.path.name, file.name), os.path.join(new_path, file.name))
            file.path = new_path
            # update vbox
            vbox_model = Vbox.objects.filter(name=vbox).first()
            vbox_model.status = 2
            vbox_model.time = datetime.datetime.now()
            # make sure that new params has been saved.
            try:
                file.save()
                vbox_model.save()
                # restore vbox
                vbox_name = file.vbox
                vbox_snapshot_name = vbox_name + "-snapshot"
                _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
            except Exception as e:
                pass

    return HttpResponse('')


def check(request):
    # check hanged files
    on_process_files = Record.objects.filter(status=1)
    cur_time = datetime.datetime.now(datetime.timezone.utc)
    for opf in on_process_files:
        diff = cur_time - opf.updated_time
        diff_minutes = (diff.days * 24 * 60) + (diff.seconds / 60)
        if diff_minutes > config('MACHINE_FILE_TIMEOUT', cast=int):
            # move file to error folder
            new_path = os.path.join(opf.path.name, "error")
            os.rename(os.path.join(opf.path.name, opf.name), os.path.join(new_path, opf.name))
            opf.path = new_path
            opf.updated_time = datetime.datetime.now()
            opf.status = 3
            opf.save()
            # restore vbox
            vbox_name = opf.vbox
            vbox_snapshot_name = vbox_name + "-snapshot"
            _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
    # check hanged vboxes
    time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=config("MACHINE_HW_TIMEOUT"))
    hanaged_vboxes = Vbox.objects.filter(status=1).filter(time__lt=time_threshold)
    for hvb in hanaged_vboxes:
        # find the file and move to error
        file = Record.objects.filter(vbox=hvb.name).filter(status=1).first()
        new_path = os.path.join(file.path.name, "error")
        os.rename(os.path.join(file.path.name, file.name), os.path.join(new_path, file.name))
        file.path = new_path
        file.response = "Uknown Error. VBox Error."
        file.updated_time = datetime.datetime.now()
        file.status = 3
        file.save()
        # restore vbox
        vbox_name = hvb.name
        vbox_snapshot_name = vbox_name + "-snapshot"
        _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
    return HttpResponse("Task completed.")


def collect(request, type):
    path = os.path.join('dataset', 'malware')
    malware = 1
    if type == "benign":
        path = os.path.join('dataset', 'benign')
        malware = 0
    files = [f for f in listdir(path) if isfile(join(path, f))]
    for f in files:
        try:
            arch = _pe_info(os.path.join(path, f))
            if arch is not None:
                if arch == "IMAGE_FILE_MACHINE_I386":
                    new_path = os.path.join(path, "x86")
                else:
                    new_path = os.path.join(path, "x64")
                os.rename(os.path.join(path, f), os.path.join(new_path, f))
                Record.objects.create(
                    name=f,
                    arch=arch,
                    path=new_path,
                    malware=malware,
                )
            else:
                # move file to not valid folder
                new_path = os.path.join(path, "notvalid")
                os.rename(os.path.join(path, f), os.path.join(new_path, f))
        except Exception as e:
            continue
        time.sleep(1)
    return HttpResponse("Files added to database.")


def vbox(request, name):
    try:
        Record.objects.create(
            name=name,
            status=0,
            time=datetime.datetime.now(),
        )
        result = "VBox added to database."
    except Exception as e:
        result = "There is some error or duplicate vbox name. Please try again."
    return HttpResponse("VBox added to database.")


def _vbox_restore(vbox_name, vbox_snapshot_name, retry_limit):
    vbox_model = Vbox.objects.filter(name=vbox_name).first()
    try:
        vboxmanage_path = config("VBOX_MANGE")
        # power off vbox
        command = vboxmanage_path + " controlvm " + vbox_name + " poweroff"
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).communicate()
        time.sleep(config("MACHINE_SLEEP_POWEROFF", cast=int))
        # revert snapshot
        command = vboxmanage_path + " snapshot " + vbox_name + " restore " + vbox_snapshot_name
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).communicate()
        time.sleep(config("MACHINE_SLEEP_RESTORE", cast=int))
        # resume vbox
        command = vboxmanage_path + " startvm " + vbox_name
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE).communicate()
        # update vbox model
        vbox_model.status = 0
        vbox_model.time = datetime.datetime.now()
        vbox_model.save()
    except Exception as e:
        if retry_limit > 0:
            retry_limit -= 1
            _vbox_restore(vbox_name, vbox_snapshot_name, retry_limit)
        else:
            vbox_model.status = 3
            vbox_model.time = datetime.datetime.now()
            vbox_model.save()
            pass


def _pe_info(file):
    try:
        pe = pefile.PE(file)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        return pefile.MACHINE_TYPE[machine]
    except pefile.PEFormatError:
        return None
