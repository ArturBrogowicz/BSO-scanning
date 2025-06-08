from gvm.connections import TLSConnection
from gvm.protocols.gmp import GMPv227
from gvm.errors import GvmError
import netifaces
from lxml import etree
import time
import smtplib
from email.message import EmailMessage
import os
def stop_all_running_tasks(gmp):
    from time import sleep
    try:
        tasks_raw = gmp.get_tasks()
        tasks_xml = etree.fromstring(tasks_raw)

        running_statuses = {"Running", "Requested", "Queued", "Started"}

        for task in tasks_xml.xpath('//task'):
            task_id = task.get('id')
            task_name = task.findtext('name')
            status_elem = task.find('status')
            status = status_elem.text if status_elem is not None else None

            if status in running_statuses:
                print(f"⏹ Zatrzymywanie taska {task_name} (ID: {task_id}) ze statusem {status}...")
                gmp.stop_task(task_id)
                # Czekaj chwilę, aby mieć pewność, że task się zatrzymał
                sleep(2)

        print(" Wszystkie aktywne taski zostały zatrzymane.")
    except Exception as e:
        print(f" Błąd podczas zatrzymywania tasków: {e}")


def get_ip_from_interface(interface="wg0"):
    try:
        iface_data = netifaces.ifaddresses(interface)
        ip_info = iface_data.get(netifaces.AF_INET)
        if not ip_info:
            raise RuntimeError(f"Brak adresu IPv4 dla interfejsu {interface}")
        return ip_info[0]["addr"]
    except Exception as e:
        raise RuntimeError(f"Nie udało się pobrać IP z interfejsu {interface}: {e}")

def connect_to_gvm():
    connection = TLSConnection(hostname='10.0.0.2', port=9390)
    gmp = GMPv227(connection)
    print(f"✅ Używana wersja GMP: {type(gmp)}")
    try:
        gmp.connect()
        gmp.authenticate('user', 'password')  # <- uzupełnij
        print("🔐 Uwierzytelniono poprawnie.")
        return gmp
    except AttributeError as ae:
        print(f"❌ Brak metody authenticate(): {ae}")
    except Exception as e:
        print(f"⚠ Błąd GMP: {e}")
    return None

def send_email_with_report(report_path, recipient_email):
    try:
        msg = EmailMessage()
        msg['Subject'] = '📄 Raport ze skanowania GVM'
        msg['From'] = 'scanner@example.com'
        msg['To'] = recipient_email
        msg.set_content('W załączniku znajduje się raport ze skanowania wykonany przez GVM.')

        with open(report_path, 'rb') as f:
            file_data = f.read()
            file_name = os.path.basename(report_path)
            msg.add_attachment(file_data, maintype='application', subtype='pdf', filename=file_name)

        with smtplib.SMTP('smtp.example.com', 587) as smtp:
            smtp.starttls()
            smtp.login('scanner@example.com', 'password')  # <-- ZMIEŃ dane
            smtp.send_message(msg)
        print(f"📧 Raport został wysłany do {recipient_email}")
    except Exception as e:
        print(f"❌ Błąd podczas wysyłania e-maila: {e}")


def wait_for_task_completion(gmp, task_id, timeout=600, interval=10):
    """
    Czeka na zakończenie taska (status 'Done') lub timeout.
    """
    from datetime import datetime, timedelta
    end_time = datetime.now() + timedelta(seconds=timeout)
    while datetime.now() < end_time:
        tasks_raw = gmp.get_tasks(filter_string=f"id={task_id}")
        tasks_xml = etree.fromstring(tasks_raw)
        task = tasks_xml.find('.//task')
        if task is not None:
            status = task.findtext('status')
            print(f"⏳ Status taska {task_id}: {status}")
            if status == 'Done':
                print(etree.tostring(task, pretty_print=True).decode())
                return True
            elif status in ['Stopped', 'Canceled', 'Error']:
                print(f"❌ Task zakończony z status: {status}")
                return False
        time.sleep(interval)
    print("⌛ Timeout oczekiwania na zakończenie taska.")
    return False

def get_report_id_for_task(gmp, task_id):
    """
    Pobiera ID raportu powiązanego z taskiem.
    """
    tasks_raw = gmp.get_tasks(filter_string=f"id={task_id}")
    tasks_xml = etree.fromstring(tasks_raw)
    task = tasks_xml.find('.//task')
    if task is not None:
        report = task.find('report')
        if report is not None:
            return report.get('id')
    return None

def create_and_start_scan(gmp, target_ip):
    try:
        # Szukaj listy portów o nazwie "Custom Full TCP"
        port_lists_raw = gmp.get_port_lists()
        port_lists_xml = etree.fromstring(port_lists_raw)

        port_list = None
        for pl in port_lists_xml.xpath("port_list"):
            name = pl.findtext("name")
            if name == "Custom Full TCP":
                port_list = pl
                break

        if port_list is not None:
            port_list_id = port_list.get("id")
            print(f"✅ Znaleziono istniejącą listę portów: {port_list_id}")
        else:
            print("ℹ Nie znaleziono listy portów 'Custom Full TCP' – tworzę nową.")
            response = gmp.create_port_list(
                name="Custom Full TCP",
                port_range="T:1-65535"  # T: dla TCP, U: dla UDP
            )
            response_xml = etree.fromstring(response)
            port_list_id = response_xml.get("id")

            if not port_list_id:
                raise RuntimeError("Nie udało się uzyskać ID nowej listy portów.")
            print(f"🆕 Utworzono port_list_id: {port_list_id}")

        # Utwórz target
        target_name = f"AutoTarget-{target_ip}"  # Oryginalna nazwa z kropkami
        target_name_alt = f"AutoTarget-{target_ip.replace('.', '_')}"  # Alternatywna nazwa z podkreślnikami
        target_id = None

        try:
            target_response = gmp.create_target(
                name=target_name,
                hosts=[target_ip],
                port_list_id=port_list_id,
                alive_test="Consider Alive",
                comment="Auto-created by script"
            )
            target_xml = etree.fromstring(target_response)

            print("📦 Odpowiedź create_target:")
            print(etree.tostring(target_xml, pretty_print=True).decode())

            if target_xml.get("status") == "400" and target_xml.get("status_text") == "Target exists already":
                print("🔁 Target już istnieje – wyszukiwanie po nazwie...")
                for name in [target_name, target_name_alt]:
                    targets_raw = gmp.get_targets(filter_string=f'name="{name}"')
                    targets_xml = etree.fromstring(targets_raw)
                    for t in targets_xml.xpath('//target'):
                        if t.findtext("name") == name:
                            target_id = t.get("id")
                            break
            else:
                target_id = target_xml.get("id")

            print(f"🆕 Utworzono nowy target: {target_id}")
        except GvmError as e:
            print(f"ℹ Błąd przy tworzeniu targetu: {e} - szukam istniejącego...")

            for name in [target_name, target_name_alt]:
                targets_raw = gmp.get_targets(filter_string=f'name="{name}"')
                targets_xml = etree.fromstring(targets_raw)

                for t in targets_xml.xpath('//target'):
                    name_elem = t.find('name')
                    if name_elem is not None and name_elem.text in [target_name, target_name_alt]:
                        target_id = t.get('id')
                        print(f"🔁 Użyto istniejącego targetu (ID: {target_id})")
                        break
                if target_id:
                    break

        if not target_id:
            try:
                print("ℹ Próba utworzenia targetu z alternatywną nazwą...")
                target_response = gmp.create_target(
                    name=target_name_alt,
                    hosts=[target_ip],
                    port_list_id=port_list_id,
                    alive_test="Consider Alive",
                    comment="Auto-created by script"
                )
                target_xml = etree.fromstring(target_response)
                target_id = target_xml.get("id")
                print(f"🆕 Utworzono nowy target (alternatywna nazwa): {target_id}")
            except GvmError as e:
                raise RuntimeError(f"Nie udało się utworzyć ani znaleźć targetu: {e}")

        print(f"🎯 Target ID: {target_id}")

        # Pobierz konfiguracje skanowania
        configs_raw = gmp.get_scan_configs()
        configs = etree.fromstring(configs_raw)

        for c in configs.xpath("config"):
            name = c.findtext("name")
            cid = c.get("id")
            print(f"📄 Config: {name} ({cid})")


        # 🔎 Znajdź oryginalny "Full and fast"
        full_fast = next(
            (c for c in configs.xpath("config") if c.findtext("name") == "Full and fast"),
            None
        )

        # 🔄 Szukaj lokalnej kopii "Full and fast - LOCAL COPY"
        local_copy = next(
            (c for c in configs.xpath("config") if c.findtext("name") == "Full and fast - LOCAL COPY"),
            None
        )

         # ✅ Jeśli nie masz lokalnej kopii, sklonuj
        if not local_copy and full_fast is not None:
            print("🔧 Tworzę lokalną kopię konfiguracji 'Full and fast'...")
            response = gmp.clone_scan_config(full_fast.get("id"))
            response_xml = etree.fromstring(response)
            config_id = response_xml.get("id")
            if not config_id:
                raise RuntimeError("Nie udało się uzyskać ID nowej konfiguracji.")
            print(f"🆕 Utworzono konfigurację (ID: {config_id})")
        else:
            config_id = local_copy.get("id") if local_copy is not None else full_fast.get("id")

        print(f"⚙ Używana konfiguracja skanu (finalna): {config_id}")

        print(f"Config ID: {config_id}")

        if not config_id:
            raise RuntimeError("Nie znaleziono konfiguracji 'Full and fast'.")
        print(f"⚙  Używana konfiguracja skanu: {config_id}")

        # Utwórz task
        task_name = f"Scan-{target_ip}"

        scanners_raw = gmp.get_scanners()
        scanners_xml = etree.fromstring(scanners_raw)

        scanner = scanners_xml.find('scanner')
        if scanner is None:
            raise RuntimeError("Nie znaleziono żadnego skanera.")
        scanner_id = scanner.get('id')
        print(f"⚙ Używany scanner_id: {scanner_id}")

        task_response = gmp.create_task(
            name=task_name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        task_xml = etree.fromstring(task_response)
        task_id = task_xml.get("id")
        print(f"📝 Utworzono task: {task_name} (ID: {task_id})")

        task_info = gmp.get_task(task_id)
        print(task_info)

        start_response = gmp.start_task(task_id=task_id)
        start_xml = etree.fromstring(start_response)
        # report_id = start_xml.get("report_id")  # Zamiast tego używamy później funkcji

        print("🚀 Skan uruchomiony, oczekiwanie na zakończenie...")

        # Monitoruj status skanu
        if wait_for_task_completion(gmp, task_id):
            report_id = get_report_id_for_task(gmp, task_id)
            if report_id:
                print(f"✅ Skan zakończony. Report ID: {report_id}")
            else:
                print("⚠ Nie znaleziono Report ID po zakończeniu skanu.")
        else:
            print("⚠ Task nie zakończył się poprawnie.")

        if report_id:
            # Pobierz raport w formacie PDF
            export_resp = gmp.get_report(report_id=report_id, report_format_id="c402cc3e-b531-11e1-9163-406186ea4fc5")  # PDF
            report_data = etree.fromstring(export_resp)
            content = report_data.findtext(".//report/content")

            import base64
            binary_data = base64.b64decode(content)

            report_file = f"report_{target_ip.replace('.', '_')}.pdf"
            with open(report_file, "wb") as f:
                f.write(binary_data)

            print(f"📄 Raport zapisany jako: {report_file}")

            # Wyślij e-mail
            send_email_with_report(report_file, "01187010@pw.edu.pl") 


    except GvmError as e:
        print(f"❌ Błąd GMP: {e}")
    except Exception as e:
        print(f"⚠ Inny błąd: {e}")

def clean_old_targets(gmp, days=1):
    from datetime import datetime, timedelta
    try:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        filter_str = f"created<{cutoff} and name~AutoTarget"
        targets_raw = gmp.get_targets(filter_string=filter_str)
        targets_xml = etree.fromstring(targets_raw)

        for target in targets_xml.xpath('//target'):
            target_id = target.get('id')
            name = target.findtext('name')
            print(f"🧹 Usuwanie starego targetu: {name} ({target_id})")
            gmp.delete_target(target_id)

    except Exception as e:
        print(f"⚠ Błąd czyszczenia starych targetów: {e}")

def main():
    try:
        target_ip = get_ip_from_interface("wg0")
        print(f"📍 Wykryty IP z wg0: {target_ip}")
    except Exception as e:
        print(e)
        return

    gmp = connect_to_gvm()
    if gmp:
        try:
            stop_all_running_tasks(gmp)
            clean_old_targets(gmp, days=1)  # Usuń targety starsze niż 1 dzień
            create_and_start_scan(gmp, target_ip)
        finally:
            try:
                gmp.disconnect()
                print("🔌 Odłączono od GVM.")
            except Exception:
                pass

if __name__ == "__main__":
    main()