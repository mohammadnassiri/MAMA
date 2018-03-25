import json

import datetime
from django.http import HttpResponse, Http404
import os
from os import listdir
from os.path import isfile, join
from django.views.decorators.csrf import csrf_exempt
from api.models import Record
import pefile

from server import settings


@csrf_exempt
def index(request):
    json_response = "0"
    if request.method == "POST":
        arch = request.POST.get('arch')
        if arch == "x86":
            arch = "IMAGE_FILE_MACHINE_I386"
        if arch == "x64":
            arch = "IMAGE_FILE_MACHINE_AMD64"
        response = Record.objects.filter(status=0).filter(arch=arch).order_by('id').first()
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
        file = Record.objects.filter(id=id).first()
        file.status = 1
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
        file.screen_shot = request.FILES.get('screen_shot')
        file.run_pe = request.POST.get('run_pe')
        file.status = 2
        file.updated_time = datetime.datetime.now()
        file.save()
    return HttpResponse('')


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
                Record.objects.create(
                    name=f,
                    arch=arch,
                    file=os.path.join(path, f),
                    malware=malware,
                )
        except Exception as e:
            pass
    return HttpResponse("Files added to database.")


def _pe_info(file):
    try:
        pe = pefile.PE(file)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        return pefile.MACHINE_TYPE[machine]
    except pefile.PEFormatError:
        return None
