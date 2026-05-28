from django.shortcuts import render, redirect
from django.conf import settings
from django.db import connection

from .models import Client


def _login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('/login')
        return view_func(request, *args, **kwargs)
    return wrapper


@_login_required
def add_client(request):
    error = None
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        phone = request.POST.get('phone', '').strip()
        address = request.POST.get('address', '').strip()
        package = request.POST.get('package', '').strip()

        if not name:
            error = "Name is required."
        else:
            if getattr(settings, 'VULNERABLE', False):
                # VULNERABLE: raw SQL — injectable and name stored unescaped
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"INSERT INTO clients_client (name, phone, address, package, created_at) "
                        f"VALUES ('{name}', '{phone}', '{address}', '{package}', NOW())"
                    )
                with connection.cursor() as cursor:
                    cursor.execute("SELECT LAST_INSERT_ID()")
                    client_id = cursor.fetchone()[0]
                return redirect(f'/clients/{client_id}/')
            else:
                client = Client.objects.create(
                    name=name, phone=phone, address=address, package=package
                )
                return redirect(f'/clients/{client.id}/')

    return render(request, 'clients/add_client.html', {'error': error})


@_login_required
def client_detail(request, client_id):
    vulnerable = getattr(settings, 'VULNERABLE', False)
    if vulnerable:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT id, name, phone, address, package FROM clients_client WHERE id={client_id}"
            )
            row = cursor.fetchone()
        if not row:
            return redirect('/clients/add')
        client = {'id': row[0], 'name': row[1], 'phone': row[2], 'address': row[3], 'package': row[4]}
    else:
        try:
            client = Client.objects.get(id=client_id)
        except Client.DoesNotExist:
            return redirect('/clients/add')

    return render(request, 'clients/client_detail.html', {'client': client, 'vulnerable': vulnerable})
