from django import forms

from api.models import Vbox


class VBoxNameForm(forms.Form):
    name = forms.CharField(label='VBox Name', max_length=255, widget=forms.TextInput(attrs={'placeholder': 'Enter VBox name ...', 'class': 'form-control'}))


class SingleVBoxRestoreForm(forms.Form):
    name = forms.ChoiceField(choices=[], widget=forms.Select(attrs={'class': 'form-control'}))
    def __init__(self, *args, **kwargs):
        super(SingleVBoxRestoreForm, self).__init__(*args, **kwargs)
        self.fields['name'].choices = [(x.name, x.name) for x in Vbox.objects.all()]


class CollectForm(forms.Form):
    type = forms.ChoiceField(choices=[('malware', 'Malware'), ('benign', 'Benign')], widget=forms.Select(attrs={'class': 'form-control'}))


