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
from api.models import Record
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
        file = Record.objects.filter(id=id).first()
        file.status = 1
        file.vbox = vbox
        file.save()
        if file:
            file_path = os.path.join(settings.BASE_DIR, file.file.name)
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
        file = Record.objects.filter(id=id).first()
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
        file.save()
        vbox_name = file.vbox
        vbox_snapshot_name = vbox_name + "-snapshot"
        # power off vbox
        vboxmanage_path = config("VBOXMANGE")
        command = vboxmanage_path + " controlvm " + vbox_name + " poweroff"
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        time.sleep(3)
        # revert snapshot
        command = vboxmanage_path + " snapshot " + vbox_name + " restore " + vbox_snapshot_name
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        time.sleep(3)
        # resume vbox
        command = vboxmanage_path + " startvm " + vbox_name
        subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    return HttpResponse('')


def collect(request, type):
    path = os.path.join('dataset', 'malware')
    malware = 1
    if type == "benign":
        path = os.path.join('dataset', 'benign')
        malware = 0
    files = [f for f in listdir(path) if isfile(join(path, f))]
    for f in files:
        time.sleep(1)
        if not f.find("NotValid_") == 0:
            try:
                arch = _pe_info(os.path.join(path, f))
                if arch is not None:
                    Record.objects.create(
                        name=f,
                        arch=arch,
                        file=os.path.join(path, f),
                        malware=malware,
                    )
                else:
                    os.rename(os.path.join(path, f), os.path.join(path, "NotValid_" + f))
            except Exception as e:
                pass
    return HttpResponse("Files added to database.")


def check(request):
    on_process_files = Record.objects.filter(status=1)
    cur_time = datetime.datetime.now(datetime.timezone.utc)
    for opf in on_process_files:
        diff = cur_time - opf.updated_time
        diff_minutes = (diff.days * 24 * 60) + (diff.seconds / 60)
        if diff_minutes > config('MACHINTIMEOUT', cast=int):
            vbox_name = opf.vbox
            vbox_snapshot_name = vbox_name + "-snapshot"
            vboxmanage_path = config("VBOXMANGE")
            # power off vbox
            command = vboxmanage_path + " controlvm " + vbox_name + " poweroff"
            subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            time.sleep(3)
            # revert snapshot
            command = vboxmanage_path + " snapshot " + vbox_name + " restore " + vbox_snapshot_name
            subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            time.sleep(3)
            # resume vbox
            command = vboxmanage_path + " startvm " + vbox_name
            subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            opf.status = 3
            opf.save()
    return HttpResponse("Task completed.")


def _pe_info(file):
    try:
        pe = pefile.PE(file)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        return pefile.MACHINE_TYPE[machine]
    except pefile.PEFormatError:
        return None
