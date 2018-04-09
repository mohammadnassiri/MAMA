import json
from decouple import config
import datetime
from django.http import HttpResponse, Http404, HttpResponseRedirect
import os
import subprocess
from os import listdir
from os.path import isfile, join
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from api.models import Record, Vbox, Option
import pefile
import time
from django.contrib import messages
from .forms import VBoxNameForm, SingleVBoxRestoreForm, CollectForm


def index(request):
    option = Option.objects.first()
    vbox_form = VBoxNameForm()
    restore_form = SingleVBoxRestoreForm()
    collect_form = CollectForm()
    vbox_count = Vbox.objects.count()
    idle_count = Record.objects.filter(status=0).count()
    pending_count = Record.objects.filter(status=1).count()
    traced_count = Record.objects.filter(status=2).count()
    error_count = Record.objects.filter(status=3).count()
    context = {
        'title': "Malware Analyzer",
        'url': config('url'),
        'pause': option.pause,
        'power': option.power,
        'vbox_form': vbox_form,
        'restore_form': restore_form,
        'collect_form': collect_form,
        'vbox_count' : vbox_count,
        'idle_count' : idle_count,
        'pending_count' : pending_count,
        'traced_count' : traced_count,
        'error_count' : error_count,
    }
    return render(request, 'api/index.html', context)


@csrf_exempt
def request(request):
    json_response = "0"
    option = Option.objects.first()
    if request.method == "POST" and option.pause == 1:
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
        vbox_model = Vbox.objects.filter(name=vbox).first()
        # update file and vbox models
        file = Record.objects.filter(id=id).first()
        if file:
            file.updated_time = datetime.datetime.now()
            file.status = 1
            file.vbox = vbox_model
            file.save()
            # update vbox model
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
        file = Record.objects.filter(id=id).first()
        vbox_model = file.vbox
        if file:
            file.response = request.POST.get('response')
            if request.FILES.get('sequence'):
                file.sequence = request.FILES.get('sequence')
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
            new_path = file.path.name
            if file.path.name.find("traced") == -1:
                new_path = os.path.join(file.path.name, "traced")
            os.rename(os.path.join(file.path.name, file.name), os.path.join(new_path, file.name))
            file.path = new_path
            # update vbox
            vbox_model.status = 2
            vbox_model.time = datetime.datetime.now()
            # make sure that new params has been saved.
            try:
                file.save()
                vbox_model.save()
                # restore vbox
                vbox_name = vbox_model.name
                vbox_snapshot_name = vbox_name + "-snapshot"
                _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
            except Exception as e:
                pass

    return HttpResponse('')


def check(request):
    result = ""
    # check poweroff status
    option = Option.objects.first()
    if option.power == 1:
        # check hanged files
        file_time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=config("MACHINE_FILE_TIMEOUT", cast=int))
        on_process_files = Record.objects.filter(status=1).filter(updated_time__lt=file_time_threshold)
        for opf in on_process_files:
            # move file to error folder. try is for sometimes moving errors
            try:
                new_path = os.path.join(opf.path.name, "error")
                os.rename(os.path.join(opf.path.name, opf.name), os.path.join(new_path, opf.name))
                opf.path = new_path
            except Exception as e:
                pass
            opf.response = "Uknown Error. File Error."
            opf.updated_time = datetime.datetime.now()
            opf.status = 3
            opf.save()
            # restore vbox
            vbox_model = opf.vbox
            vbox_name = vbox_model.name
            vbox_snapshot_name = vbox_name + "-snapshot"
            _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
        # check hanged vboxes
        vbox_time_threshold = datetime.datetime.now() - datetime.timedelta(minutes=config("MACHINE_HW_TIMEOUT", cast=int))
        hanaged_vboxes = Vbox.objects.filter(time__lt=vbox_time_threshold)
        for hvb in hanaged_vboxes:
            # find the file and move to error exception let it go to upper scope
            try:
                file = Record.objects.filter(vbox=hvb.id).filter(status=1).first()
                new_path = os.path.join(file.path.name, "error")
                os.rename(os.path.join(file.path.name, file.name), os.path.join(new_path, file.name))
                file.path = new_path
                file.response = "Uknown Error. VBox Error."
                file.updated_time = datetime.datetime.now()
                file.status = 3
                file.save()
            except Exception as e:
                pass
            # restore vbox
            vbox_name = hvb.name
            vbox_snapshot_name = vbox_name + "-snapshot"
            _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
            result = "Task completed."
    else:
        result = "System powered off."
    return HttpResponse(result)


def collect(request):
    if request.method == "GET":
        result = True
        form = CollectForm(request.GET)
        if form.is_valid():
            type = form.cleaned_data['type']
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
                        new_f = f.replace(' ', '_')
                        os.rename(os.path.join(path, f), os.path.join(new_path, new_f))
                        Record.objects.create(
                            name=new_f,
                            arch=arch,
                            path=new_path,
                            malware=malware,
                        )
                    else:
                        # move file to not valid folder
                        new_path = os.path.join(path, "notvalid")
                        os.rename(os.path.join(path, f), os.path.join(new_path, f))
                except Exception as e:
                    result = False
                    pass
                time.sleep(1)
            if result:
                messages.success(request, "Files added to database.")
            else:
                messages.error(request, "There is some errors. Check the folder.")
        else:
            errors = form.errors
            messages.error(request, errors)
        next = request.POST.get('next', '/api')
        return HttpResponseRedirect(next)


def vbox(request):
    if request.method == "GET":
        form = VBoxNameForm(request.GET)
        if form.is_valid():
            try:
                Vbox.objects.create(
                    name=form.cleaned_data['name'],
                    status=0,
                    time=datetime.datetime.now(),
                )
                messages.success(request, "VBox added to database.")
            except Exception as e:
                messages.error(request, "There is some error or duplicate vbox name. Please try again.")
        else:
            errors = form.errors
            messages.error(request, errors)
        next = request.POST.get('next', '/api')
        return HttpResponseRedirect(next)


def restore(request):
    if request.method == "GET":
        form = SingleVBoxRestoreForm(request.GET)
        if form.is_valid():
            try:
                vbox_name = form.cleaned_data['name']
                vbox_snapshot_name = vbox_name + "-snapshot"
                _vbox_restore(vbox_name, vbox_snapshot_name, config("MACHINE_RESTORE_RETRY_LIMIT", cast=int))
                messages.success(request, "VBox has been restart.")
            except Exception as e:
                messages.error(request, "Please try again later.")
        else:
            errors = form.errors
            messages.error(request, errors)
        next = request.POST.get('next', '/api')
        return HttpResponseRedirect(next)


def option(request, param):
    type = True
    option = Option.objects.first()
    if option == None:
        Option.objects.create(
            pause=0,
            power=0,
        )
        option = Option.objects.first()
    if param == "resume":
        option.pause = 1
        result = "System resumed."
    elif param == "pause":
        option.pause = 0
        result = "System paused."
    elif param == "poweroff":
        option.pause = 0
        option.power = 0
        result, type = _vbox_power_off()
    elif param == "poweron":
        option.pause = 1
        option.power = 1
        result, type = _vbox_power_on()
    else:
        result = "Please give parameter."
    try:
        option.save()
        if type:
            messages.success(request, result)
        else:
            messages.error(request, result)
    except Exception as e:
        messages.error(request, "Please try again later.")
    next = request.POST.get('next', '/api')
    return HttpResponseRedirect(next)


def _vbox_power_off():
    type = True
    vboxes = Vbox.objects.all()
    result = "Virtual boxes powered off."
    for vm in vboxes:
        try:
            vboxmanage_path = config("VBOX_MANAGE")
            # power off vbox
            command = vboxmanage_path + " controlvm " + vm.name + " poweroff"
            subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            time.sleep(config("MACHINE_SLEEP_POWEROFF", cast=int))
            # update vbox model
            vm.status = 0
            vm.time = datetime.datetime.now()
            vm.save()
        except Exception as e:
            result = "Please try again later."
            type = False
            pass
    return result, type


def _vbox_power_on():
    type = True
    vboxes = Vbox.objects.all()
    result = "Virtual boxes powered on."
    for vm in vboxes:
        try:
            vboxmanage_path = config("VBOX_MANAGE")
            # power on vbox
            command = vboxmanage_path + " startvm " + vm.name
            subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE).communicate()
            time.sleep(config("MACHINE_SLEEP_POWEROFF", cast=int))
            # update vbox model
            vm.status = 0
            vm.time = datetime.datetime.now()
            vm.save()
        except Exception as e:
            result = "Please try again later."
            type = False
            pass
    return result, type


def _vbox_restore(vbox_name, vbox_snapshot_name, retry_limit):
    vbox_model = Vbox.objects.filter(name=vbox_name).first()
    try:
        vboxmanage_path = config("VBOX_MANAGE")
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
