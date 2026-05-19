import re
import html

import bleach
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from .models import Product, Category, Order, OrderItem


# ---------------------------------------------------------------------------
# Utilidades de validación
# ---------------------------------------------------------------------------

def _sanitize(text: str) -> str:
    return bleach.clean(text, tags=[], strip=True)


def validate_name(name: str) -> str:
    name = name.strip()
    if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$', name):
        raise ValidationError('Solo se permiten letras y espacios.')
    if '   ' in name:
        raise ValidationError('Demasiados espacios consecutivos.')
    return name


def validate_phone(phone: str) -> str:
    clean = re.sub(r'[\s\-\(\)]', '', phone)
    if not re.match(r'^\d{10}$', clean):
        raise ValidationError('El teléfono debe tener exactamente 10 dígitos.')
    return clean


def validate_address(address: str) -> str:
    address = address.strip()
    if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s,.\-#]+$', address):
        raise ValidationError('La dirección contiene caracteres no permitidos.')
    if len(address) > 500:
        raise ValidationError('La dirección no puede superar 500 caracteres.')
    return _sanitize(address)


# ---------------------------------------------------------------------------
# Formularios de administración
# ---------------------------------------------------------------------------

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 200}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 1000}),
        }

    def clean_name(self):
        name = _sanitize(self.cleaned_data.get('name', '').strip())
        if len(name) < 2:
            raise ValidationError('El nombre debe tener al menos 2 caracteres.')
        return name

    def clean_description(self):
        desc = self.cleaned_data.get('description', '')
        return _sanitize(desc.strip()) if desc else desc


class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image',
                  'roast_level', 'origin', 'format', 'weight', 'is_available']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 200}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 2000}),
            'price': forms.NumberInput(attrs={'class': 'form-control', 'min': '0.01', 'step': '0.01'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control', 'min': '0'}),
            'roast_level': forms.Select(attrs={'class': 'form-select'}),
            'origin': forms.TextInput(attrs={'class': 'form-control', 'maxlength': 100}),
            'format': forms.Select(attrs={'class': 'form-select'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control', 'min': '1'}),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean_name(self):
        name = _sanitize(self.cleaned_data.get('name', '').strip())
        if len(name) < 2:
            raise ValidationError('El nombre debe tener al menos 2 caracteres.')
        return name

    def clean_description(self):
        return _sanitize(self.cleaned_data.get('description', '').strip())

    def clean_origin(self):
        origin = _sanitize(self.cleaned_data.get('origin', '').strip())
        if not re.match(r'^[A-Za-z\s\-,\.]+$', origin):
            raise ValidationError('El origen solo puede contener letras, espacios y guiones.')
        return origin

    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is not None:
            if price <= 0:
                raise ValidationError('El precio debe ser mayor que 0.')
            if price > 999999.99:
                raise ValidationError('El precio no puede superar $999,999.99.')
        return price

    def clean_stock(self):
        stock = self.cleaned_data.get('stock')
        if stock is not None:
            if stock < 0:
                raise ValidationError('El stock no puede ser negativo.')
            if stock > 999999:
                raise ValidationError('El stock no puede superar 999,999 unidades.')
        return stock

    def clean_weight(self):
        weight = self.cleaned_data.get('weight')
        if weight is not None:
            if weight <= 0:
                raise ValidationError('El peso debe ser mayor que 0.')
            if weight > 10000:
                raise ValidationError('El peso no puede superar 10,000 gramos.')
        return weight


# ---------------------------------------------------------------------------
# Formularios de autenticación
# ---------------------------------------------------------------------------

class LoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Usuario', 'maxlength': 150})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Contraseña'})
    )

    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        return _sanitize(username.strip())


class RegistrationForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nombre'}),
    )
    last_name = forms.CharField(
        max_length=30, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Apellido'}),
    )
    email = forms.EmailField(
        max_length=254, required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Correo electrónico'}),
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Usuario'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Contraseña'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control', 'placeholder': 'Confirmar contraseña'})

    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        if User.objects.filter(email=email).exists():
            raise ValidationError('Este correo ya está registrado.')
        return email

    def clean_first_name(self):
        return validate_name(self.cleaned_data.get('first_name', ''))

    def clean_last_name(self):
        return validate_name(self.cleaned_data.get('last_name', ''))

    def clean_username(self):
        username = _sanitize(self.cleaned_data.get('username', '').strip())
        if not re.match(r'^[a-zA-Z0-9_@+.\-]+$', username):
            raise ValidationError('El usuario solo puede contener letras, números y @/./+/-/_')
        return username


class ProfileUpdateForm(forms.ModelForm):
    phone = forms.CharField(
        max_length=15, required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '1234567890',
            'pattern': r'\d{10}',
            'title': 'Exactamente 10 dígitos',
        }),
    )
    address = forms.CharField(
        max_length=500, required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Dirección completa'}),
    )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nombre'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Apellido'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Correo electrónico'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError('Este correo ya está en uso por otra cuenta.')
        return email

    def clean_first_name(self):
        return validate_name(self.cleaned_data.get('first_name', ''))

    def clean_last_name(self):
        return validate_name(self.cleaned_data.get('last_name', ''))

    def clean_phone(self):
        phone = self.cleaned_data.get('phone', '')
        return validate_phone(phone) if phone else phone

    def clean_address(self):
        address = self.cleaned_data.get('address', '')
        return validate_address(address) if address else address


# ---------------------------------------------------------------------------
# Formulario de checkout
# ---------------------------------------------------------------------------

class CheckoutForm(forms.Form):
    first_name = forms.CharField(
        max_length=30, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nombre'}),
    )
    last_name = forms.CharField(
        max_length=30, required=True,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Apellido'}),
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Correo electrónico'}),
    )
    phone = forms.CharField(
        max_length=10, min_length=10, required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '1234567890',
            'pattern': r'\d{10}',
            'inputmode': 'numeric',
            'oninput': 'this.value = this.value.replace(/[^0-9]/g, "").substring(0, 10)',
        }),
    )
    shipping_address = forms.CharField(
        max_length=500, required=True,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Dirección de envío completa'}),
    )

    def _clean_name_field(self, value: str) -> str:
        value = _sanitize(html.escape(value))
        if not re.match(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ\s]+$', value.strip()):
            raise ValidationError('Solo se permiten letras y espacios.')
        if len(value.strip()) < 2:
            raise ValidationError('Debe tener al menos 2 caracteres.')
        if '   ' in value:
            raise ValidationError('Demasiados espacios consecutivos.')
        return value.strip()

    def clean_first_name(self):
        return self._clean_name_field(self.cleaned_data.get('first_name', ''))

    def clean_last_name(self):
        return self._clean_name_field(self.cleaned_data.get('last_name', ''))

    def clean_email(self):
        email = _sanitize(html.escape(self.cleaned_data.get('email', '')))
        return email.lower().strip()

    def clean_phone(self):
        phone = _sanitize(html.escape(self.cleaned_data.get('phone', '')))
        clean = re.sub(r'[^0-9]', '', phone)
        if len(clean) != 10:
            raise ValidationError('El teléfono debe tener exactamente 10 dígitos.')
        return clean

    def clean_shipping_address(self):
        address = _sanitize(html.escape(self.cleaned_data.get('shipping_address', '')))
        address = address.strip()
        if not re.match(r'^[a-zA-Z0-9áéíóúÁÉÍÓÚñÑüÜ\s,.\-#]+$', address):
            raise ValidationError('La dirección contiene caracteres no válidos.')
        if len(address) < 5:
            raise ValidationError('La dirección debe tener al menos 5 caracteres.')
        if len(address) > 500:
            raise ValidationError('La dirección no puede superar 500 caracteres.')
        return address


# ---------------------------------------------------------------------------
# Formularios de administración de órdenes
# ---------------------------------------------------------------------------

class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ['status', 'shipping_address']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'shipping_address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'maxlength': 500}),
        }

    def clean_shipping_address(self):
        address = self.cleaned_data.get('shipping_address', '')
        return validate_address(address) if address else address


class OrderItemForm(forms.ModelForm):
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 999}),
        }

    def clean_quantity(self):
        qty = self.cleaned_data.get('quantity')
        if qty is not None:
            if qty <= 0:
                raise ValidationError('La cantidad debe ser mayor que 0.')
            if qty > 999:
                raise ValidationError('La cantidad no puede superar 999.')
        return qty
