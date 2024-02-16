from cryptography.hazmat._oid import ExtendedKeyUsageOID
from django.db.models import Max
from django.http import HttpResponse
from django.shortcuts import render
from .models import CA, Server, Client
from django.db.models import Count

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import ipaddress
import random


# --------------------------------- Генерация уникального серийного номера ---------------------------------
def generateSerialNum():

    # Получение текущей даты и времени
    now = datetime.now()

    # Форматирование даты и времени в строку в требуемом формате
    formatted_string = now.strftime("%d%m%y%H%M%S") + f"{int(now.microsecond / 1000):03d}" + f"{random.randint(0, 999)}"

    # Преобразование строки в число
    return int(formatted_string)


# --------------------------------- Генерация приватного ключа ---------------------------------
def generateKey():

    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )


def index(request):
    return HttpResponse("VPN")


def CACreate(request):

    max_id = generateSerialNum()
    organization = 'ORG'
    cn = 'CA'

    # Генерация приватного ключа
    private_key = generateKey()

    # Определение шаблона для сертификата
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # Создание самоподписанного сертификата
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        max_id  # Серийный номер
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Установка срока действия сертификата
        datetime.utcnow() + timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True,
                      content_commitment=False, data_encipherment=False, encipher_only=False, decipher_only=False,
                      key_agreement=False),
        critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Сохранение приватного ключа в переменную
    private_key_pem = (private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )).decode('utf-8')

    # Сохранение сертификата в переменную
    certificate_pem = (certificate.public_bytes(serialization.Encoding.PEM)).decode('utf-8')

    name = "myCA_" + str(max_id)
    description = "descCA_" + str(max_id)
    key = private_key_pem
    cert = certificate_pem

    # Создание и сохранение нового экземпляра модели CA
    ca = CA(name=name, description=description, key=key, cert=cert, organization=organization, cn=cn)
    ca.save()

    print(max_id)

    # Ответ, подтверждающий успешное создание
    return HttpResponse("CA успешно создана")


def ServerCreate(request):

    serial_num = generateSerialNum()
    organization = 'SERVER ORG'
    cn = 'SERVER'

    # Преобразование строки IP-адреса в объект ipaddress
    ip_address = ipaddress.ip_address('5.101.44.90')

    # Загрузка приватного ключа ЦС
    try:
        # Получение записи с максимальным ID
        ca_record_with_max_id = CA.objects.all().order_by('-id').first()
        if ca_record_with_max_id:

            # Генерация приватного ключа сервера
            server_private_key = generateKey()

            # Сохранение приватного ключа в переменную
            private_key_pem = (server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )).decode('utf-8')

            # Создание запроса на сертификат сервера (CSR)
            server_name = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
            csr = x509.CertificateSigningRequestBuilder().subject_name(server_name).sign(server_private_key,
                                                                                         hashes.SHA256(),
                                                                                         default_backend())

            cakey_utf8 = ca_record_with_max_id.key
            cacert_utf8 = ca_record_with_max_id.cert
            max_id = ca_record_with_max_id.id

            ca_private_key = serialization.load_pem_private_key(
                cakey_utf8.encode('utf-8'),
                password=None,
                backend=default_backend()
            )

            ca_cert = x509.load_pem_x509_certificate(cacert_utf8.encode('utf-8'), default_backend())

            # Подписание CSR ключом ЦС
            server_cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                serial_num  # Серийный номер
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                # Срок действия сертификата
                datetime.utcnow() + timedelta(days=3650)  # 3650 дней
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            ).add_extension(
                x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                              data_encipherment=False,
                              key_agreement=False, encipher_only=False, decipher_only=False, key_cert_sign=False,
                              crl_sign=False),
                critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True
            ).add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ip_address)]),
                critical=False
            ).sign(ca_private_key, hashes.SHA256(), default_backend())

            # Сохранение сертификата в переменную
            certificate_pem = (server_cert.public_bytes(serialization.Encoding.PEM)).decode('utf-8')

            name = "Server_" + str(serial_num)
            description = "descServer_" + str(serial_num)
            key = private_key_pem
            cert = certificate_pem

            # Создание и сохранение нового экземпляра модели CA
            server = Server(name=name, description=description, key=key, cert=cert, ca_id=max_id, organization=organization, cn=cn)
            server.save()


        else:
            ca_private_key = None  # В случае, если записей в таблице нет
            ca_cert = None
    except CA.DoesNotExist:
        ca_private_key = None  # В случае ошибки, например, если таблица пуста
        ca_cert = None

    print(ca_private_key)
    print(ca_cert)


    # Ответ, подтверждающий успешное создание
    return HttpResponse("Server успешно создана")


def ClientCreate(request):

    serial_num = generateSerialNum()
    organization = 'Client'
    cn = 'client1'
    user_id = 'client1'
    count_server = Server.objects.all().order_by('id').count()
    num_server = 0

    try:
        # Выбираем все записи Server
        servers = Server.objects.all().order_by('id')
        # Получение записи CA с максимальным ID
        ca = CA.objects.all().order_by('-id').first()
        if servers and ca:
            for server in servers:

                client_count = Client.objects.filter(server_id=server.id).count()
                #print(client_count)  # Пример вывода имени каждого сервера

                if client_count <= 3:

                    # Генерация приватного ключа клиента
                    client_private_key = generateKey()

                    # Сохранение приватного ключа в переменную
                    private_key_pem = (client_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode('utf-8')

                    # Создание запроса на сертификат сервера (CSR)
                    client_name = x509.Name([
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                        x509.NameAttribute(NameOID.COMMON_NAME, cn),
                        x509.NameAttribute(NameOID.USER_ID, user_id),
                    ])
                    csr = x509.CertificateSigningRequestBuilder().subject_name(client_name).sign(client_private_key,
                                                                                                 hashes.SHA256(),
                                                                                                 default_backend())

                    # получаем из БД ключ и сертификат сервера в формате utf8
                    cakey_utf8 = ca.key
                    cacert_utf8 = ca.cert
                    server_id = server.id

                    # преобразуем ключ и сертификат ЦС из формата utf8 в бинарный вид
                    ca_private_key = serialization.load_pem_private_key(
                        cakey_utf8.encode('utf-8'),
                        password=None,
                        backend=default_backend()
                    )

                    ca_cert = x509.load_pem_x509_certificate(cacert_utf8.encode('utf-8'), default_backend())


                    # Создание сертификата клиента
                    client_cert = x509.CertificateBuilder().subject_name(
                        csr.subject  # Имя субъекта из CSR
                    ).issuer_name(
                        ca_cert.subject  # Имя издателя из сертификата сервера
                    ).public_key(
                        csr.public_key()  # Публичный ключ из CSR
                    ).serial_number(
                        serial_num
                    ).not_valid_before(
                        datetime.utcnow()
                    ).not_valid_after(
                        datetime.utcnow() + timedelta(days=365)  # Срок действия сертификата клиента
                    ).add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True
                    ).add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
                    ).add_extension(
                        x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                      data_encipherment=False, key_agreement=False, encipher_only=False,
                                      decipher_only=False, key_cert_sign=False, crl_sign=False),
                        critical=True
                    ).add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
                    ).add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
                    ).sign(
                        private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend()
                    )

                    # ----------------------------------------------------------------------------

                    # Сохранение сертификата в переменную
                    certificate_pem = (client_cert.public_bytes(serialization.Encoding.PEM)).decode('utf-8')

                    name = "Client_" + str(serial_num)
                    description = "Client_" + str(serial_num)
                    key = private_key_pem
                    cert = certificate_pem

                    # Создание и сохранение нового экземпляра модели CA
                    client = Client(name=name, description=description, key=key, cert=cert, server_id=server_id, organization=organization, cn=cn, user_id=user_id)
                    client.save()

                    break

                else:
                    num_server += 1




            # Если лимит клиентов превышен
            if count_server == num_server:
                print('Лимит клиентов превышен')

        else:
            print("error")
    except CA.DoesNotExist:
        print("error")

    # server_count = Server.objects.filter(ca_id=max_id).count()



    # Ответ, подтверждающий успешное создание
    return HttpResponse("Client успешно создан")