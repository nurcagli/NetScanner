import scapy.all as scapy
import optparse

#1)arp_request
#2)broadcast ( request paketi broadcast yayın ile gonderılecek )
#3)response

def get_user_input():
    parse_object = optparse.OptionParser() #optparse kütüphanesinin OptionParser sınıfından bir örnek oluşturur.
    # Bu, komut satırı argümanlarını işlemek için bir araç sağlar

    parse_object.add_option("-i","--ipaddress", dest="ip_address",help="Enter IP Address")
    # Bu satır, parse_object nesnesine bir seçenek ekler. -i veya --ipaddress seçenekleriyle IP adresi girilmesini bekler. 
    # dest parametresi, kullanıcı girdisinin nereye atanacağını belirtir (burada ip_address adlı bir öğeye atanır).
    # help parametresi, kullanıcıya bu seçeneğin ne için olduğunu açıklayan bir metin sağlar.

    (user_input,arguments) = parse_object.parse_args()
    # Bu satır, kullanıcının girdisini alır ve parse_args() yöntemini kullanarak bu girdiyi işler. 
    # ve kullanıcı girdisini (user_input) ve diğer komut satırı argümanlarını (arguments) ayırır.

    if not user_input.ip_address:
        print("Enter IP Address")

    return user_input

def scan_my_network(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet  # iki paketin birleştirilerek gonderilmesi gerek.
    (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=1) # srp,scapyde birleştirilmiş paketlerın gonderılmesı ıcın kullanılıyor.
    answered_list.summary() #yanıtın duzgun formatta goruntulenmesı ıcın.

user_ip_address = get_user_input()
scan_my_network(user_ip_address.ip_address)