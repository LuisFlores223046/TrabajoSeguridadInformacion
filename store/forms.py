from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Product, Category, Customer, Order, OrderItem

class CategoryForm(forms.ModelForm):
    """Formulario para crear y editar categorías"""
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class ProductForm(forms.ModelForm):
    """Formulario para crear y editar productos"""
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image', 
                 'roast_level', 'origin', 'format', 'weight', 'is_available']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'price': forms.NumberInput(attrs={'class': 'form-control'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control'}),
            'roast_level': forms.Select(attrs={'class': 'form-select'}),
            'origin': forms.TextInput(attrs={'class': 'form-control'}),
            'format': forms.Select(attrs={'class': 'form-select'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control'}),
            'is_available': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }

class LoginForm(AuthenticationForm):
    """Formulario de login con estilos Bootstrap"""
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))

class RegistrationForm(UserCreationForm):
    """Formulario de registro con campos adicionales"""
    first_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(max_length=30, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(max_length=254, required=True, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        """Añade clases Bootstrap a los campos heredados"""
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})

class OrderForm(forms.ModelForm):
    """Formulario para actualizar órdenes"""
    class Meta:
        model = Order
        fields = ['status', 'shipping_address']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'shipping_address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

class OrderItemForm(forms.ModelForm):
    """Formulario para añadir/editar ítems de una orden"""
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']
        widgets = {
            'product': forms.Select(attrs={'class': 'form-select'}),
            'quantity': forms.NumberInput(attrs={'class': 'form-control', 'min': 1}),
        }