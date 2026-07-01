import type { ResourceLanguage } from 'i18next';

type TranslationMap = Record<string, string>;

const languageAliases: Record<string, string> = {
  no: 'nb',
  sv: 'se'
};

const networkExtras: Record<string, TranslationMap> = {
  ca: {
    'settings.network.tls.rebootTitle': 'NanoKVM es reiniciarà',
    'settings.network.tls.rebootDesc':
      'El canvi de protocol requereix reiniciar el dispositiu. El navegador canviarà a la nova adreça al cap de {{seconds}} segons:',
    'settings.network.tls.rebootOk': 'Aplica i reinicia',
    'settings.network.tls.rebootCancel': 'Cancel·la',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      "Configura l'adreçament IPv6 per a la interfície amb cable",
    'settings.network.ipv6.disabled': 'Desactivat',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manual',
    'settings.network.ipv6.apply': 'Aplica',
    'settings.network.ipv6.status': 'Estat IPv6',
    'settings.network.ipv6.interface': 'Interfície',
    'settings.network.ipv6.state': 'Estat',
    'settings.network.ipv6.router': 'Encaminador',
    'settings.network.ipv6.addresses': 'Adreces',
    'settings.network.ipv6.dhcpv6Client': 'Client DHCPv6',
    'settings.network.ipv6.notInstalled': 'No instal·lat',
    'settings.network.ipv6.manualSettings': 'IPv6 manual',
    'settings.network.ipv6.ipAddress': 'Adreça IPv6',
    'settings.network.ipv6.prefix': 'Prefix',
    'settings.network.ipv6.invalidManual':
      'Introdueix una adreça IPv6, un prefix i un encaminador vàlids',
    'settings.network.ipv6.clientMissing':
      "El client DHCPv6 no està instal·lat. Instal·la primer l'actualització raw del sistema corresponent.",
    'settings.network.ipv6.saved': 'Configuració IPv6 desada',
    'settings.network.ipv6.saveFailed': "No s'ha pogut desar la configuració IPv6",
    'settings.network.ipv6.loadFailed': "No s'ha pogut carregar la configuració IPv6",
    'settings.network.ipv6.unsaved': 'Canvis no desats'
  },
  cz: {
    'settings.network.tls.rebootTitle': 'NanoKVM se restartuje',
    'settings.network.tls.rebootDesc':
      'Změna protokolu vyžaduje restart zařízení. Prohlížeč se po {{seconds}} sekundách přepne na novou adresu:',
    'settings.network.tls.rebootOk': 'Použít a restartovat',
    'settings.network.tls.rebootCancel': 'Zrušit',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Konfigurace adresování IPv6 pro kabelové rozhraní',
    'settings.network.ipv6.disabled': 'Zakázáno',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Ručně',
    'settings.network.ipv6.apply': 'Použít',
    'settings.network.ipv6.status': 'Stav IPv6',
    'settings.network.ipv6.interface': 'Rozhraní',
    'settings.network.ipv6.state': 'Stav',
    'settings.network.ipv6.router': 'Směrovač',
    'settings.network.ipv6.addresses': 'Adresy',
    'settings.network.ipv6.dhcpv6Client': 'Klient DHCPv6',
    'settings.network.ipv6.notInstalled': 'Není nainstalováno',
    'settings.network.ipv6.manualSettings': 'Ruční IPv6',
    'settings.network.ipv6.ipAddress': 'Adresa IPv6',
    'settings.network.ipv6.prefix': 'Prefix',
    'settings.network.ipv6.invalidManual': 'Zadejte platnou adresu IPv6, prefix a směrovač',
    'settings.network.ipv6.clientMissing':
      'Klient DHCPv6 není nainstalován. Nejprve nainstalujte odpovídající raw aktualizaci systému.',
    'settings.network.ipv6.saved': 'Nastavení IPv6 uloženo',
    'settings.network.ipv6.saveFailed': 'Nastavení IPv6 se nepodařilo uložit',
    'settings.network.ipv6.loadFailed': 'Nastavení IPv6 se nepodařilo načíst',
    'settings.network.ipv6.unsaved': 'Neuložené změny'
  },
  da: {
    'settings.network.tls.rebootTitle': 'NanoKVM genstarter',
    'settings.network.tls.rebootDesc':
      'Protokolændringen kræver genstart af enheden. Browseren skifter til den nye adresse efter {{seconds}} sekunder:',
    'settings.network.tls.rebootOk': 'Anvend og genstart',
    'settings.network.tls.rebootCancel': 'Annuller',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Konfigurer IPv6-adressering for den kablede grænseflade',
    'settings.network.ipv6.disabled': 'Deaktiveret',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuel',
    'settings.network.ipv6.apply': 'Anvend',
    'settings.network.ipv6.status': 'IPv6-status',
    'settings.network.ipv6.interface': 'Grænseflade',
    'settings.network.ipv6.state': 'Tilstand',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Adresser',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6-klient',
    'settings.network.ipv6.notInstalled': 'Ikke installeret',
    'settings.network.ipv6.manualSettings': 'Manuel IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-adresse',
    'settings.network.ipv6.prefix': 'Præfiks',
    'settings.network.ipv6.invalidManual': 'Angiv en gyldig IPv6-adresse, præfiks og router',
    'settings.network.ipv6.clientMissing':
      'DHCPv6-klienten er ikke installeret. Installer først den matchende raw-systemopdatering.',
    'settings.network.ipv6.saved': 'IPv6-indstillinger gemt',
    'settings.network.ipv6.saveFailed': 'Kunne ikke gemme IPv6-indstillinger',
    'settings.network.ipv6.loadFailed': 'Kunne ikke indlæse IPv6-indstillinger',
    'settings.network.ipv6.unsaved': 'Ikke-gemte ændringer'
  },
  de: {
    'settings.network.tls.rebootTitle': 'NanoKVM wird neu gestartet',
    'settings.network.tls.rebootDesc':
      'Die Protokolländerung erfordert einen Neustart des Geräts. Der Browser wechselt nach {{seconds}} Sekunden zur neuen Adresse:',
    'settings.network.tls.rebootOk': 'Übernehmen und neu starten',
    'settings.network.tls.rebootCancel': 'Abbrechen',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      'IPv6-Adressierung für die kabelgebundene Schnittstelle konfigurieren',
    'settings.network.ipv6.disabled': 'Deaktiviert',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuell',
    'settings.network.ipv6.apply': 'Übernehmen',
    'settings.network.ipv6.status': 'IPv6-Status',
    'settings.network.ipv6.interface': 'Schnittstelle',
    'settings.network.ipv6.state': 'Status',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Adressen',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6-Client',
    'settings.network.ipv6.notInstalled': 'Nicht installiert',
    'settings.network.ipv6.manualSettings': 'Manuelles IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-Adresse',
    'settings.network.ipv6.prefix': 'Präfix',
    'settings.network.ipv6.invalidManual':
      'Bitte eine gültige IPv6-Adresse, ein Präfix und einen Router eingeben',
    'settings.network.ipv6.clientMissing':
      'Der DHCPv6-Client ist nicht installiert. Installieren Sie zuerst das passende Raw-Systemupdate.',
    'settings.network.ipv6.saved': 'IPv6-Einstellungen gespeichert',
    'settings.network.ipv6.saveFailed': 'IPv6-Einstellungen konnten nicht gespeichert werden',
    'settings.network.ipv6.loadFailed': 'IPv6-Einstellungen konnten nicht geladen werden',
    'settings.network.ipv6.unsaved': 'Ungespeicherte Änderungen'
  },
  es: {
    'settings.network.tls.rebootTitle': 'NanoKVM se reiniciará',
    'settings.network.tls.rebootDesc':
      'El cambio de protocolo requiere reiniciar el dispositivo. El navegador cambiará a la nueva dirección después de {{seconds}} segundos:',
    'settings.network.tls.rebootOk': 'Aplicar y reiniciar',
    'settings.network.tls.rebootCancel': 'Cancelar',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      'Configurar direccionamiento IPv6 para la interfaz cableada',
    'settings.network.ipv6.disabled': 'Desactivado',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manual',
    'settings.network.ipv6.apply': 'Aplicar',
    'settings.network.ipv6.status': 'Estado de IPv6',
    'settings.network.ipv6.interface': 'Interfaz',
    'settings.network.ipv6.state': 'Estado',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Direcciones',
    'settings.network.ipv6.dhcpv6Client': 'Cliente DHCPv6',
    'settings.network.ipv6.notInstalled': 'No instalado',
    'settings.network.ipv6.manualSettings': 'IPv6 manual',
    'settings.network.ipv6.ipAddress': 'Dirección IPv6',
    'settings.network.ipv6.prefix': 'Prefijo',
    'settings.network.ipv6.invalidManual':
      'Introduce una dirección IPv6, un prefijo y un router válidos',
    'settings.network.ipv6.clientMissing':
      'El cliente DHCPv6 no está instalado. Instala primero la actualización raw del sistema correspondiente.',
    'settings.network.ipv6.saved': 'Configuración IPv6 guardada',
    'settings.network.ipv6.saveFailed': 'No se pudo guardar la configuración IPv6',
    'settings.network.ipv6.loadFailed': 'No se pudo cargar la configuración IPv6',
    'settings.network.ipv6.unsaved': 'Cambios sin guardar'
  },
  fr: {
    'settings.network.tls.rebootTitle': 'NanoKVM va redémarrer',
    'settings.network.tls.rebootDesc':
      "Le changement de protocole nécessite un redémarrage de l'appareil. Le navigateur passera à la nouvelle adresse après {{seconds}} secondes:",
    'settings.network.tls.rebootOk': 'Appliquer et redémarrer',
    'settings.network.tls.rebootCancel': 'Annuler',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': "Configurer l'adressage IPv6 de l'interface filaire",
    'settings.network.ipv6.disabled': 'Désactivé',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuel',
    'settings.network.ipv6.apply': 'Appliquer',
    'settings.network.ipv6.status': 'État IPv6',
    'settings.network.ipv6.interface': 'Interface',
    'settings.network.ipv6.state': 'État',
    'settings.network.ipv6.router': 'Routeur',
    'settings.network.ipv6.addresses': 'Adresses',
    'settings.network.ipv6.dhcpv6Client': 'Client DHCPv6',
    'settings.network.ipv6.notInstalled': 'Non installé',
    'settings.network.ipv6.manualSettings': 'IPv6 manuel',
    'settings.network.ipv6.ipAddress': 'Adresse IPv6',
    'settings.network.ipv6.prefix': 'Préfixe',
    'settings.network.ipv6.invalidManual':
      'Saisissez une adresse IPv6, un préfixe et un routeur valides',
    'settings.network.ipv6.clientMissing':
      "Le client DHCPv6 n'est pas installé. Installez d'abord la mise à jour système raw correspondante.",
    'settings.network.ipv6.saved': 'Paramètres IPv6 enregistrés',
    'settings.network.ipv6.saveFailed': "Échec de l'enregistrement des paramètres IPv6",
    'settings.network.ipv6.loadFailed': 'Échec du chargement des paramètres IPv6',
    'settings.network.ipv6.unsaved': 'Modifications non enregistrées'
  },
  hu: {
    'settings.network.tls.rebootTitle': 'A NanoKVM újraindul',
    'settings.network.tls.rebootDesc':
      'A protokoll módosítása az eszköz újraindítását igényli. A böngésző {{seconds}} másodperc után az új címre vált:',
    'settings.network.tls.rebootOk': 'Alkalmazás és újraindítás',
    'settings.network.tls.rebootCancel': 'Mégse',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'IPv6-címzés beállítása a vezetékes interfészen',
    'settings.network.ipv6.disabled': 'Letiltva',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Kézi',
    'settings.network.ipv6.apply': 'Alkalmaz',
    'settings.network.ipv6.status': 'IPv6 állapot',
    'settings.network.ipv6.interface': 'Interfész',
    'settings.network.ipv6.state': 'Állapot',
    'settings.network.ipv6.router': 'Útvonalválasztó',
    'settings.network.ipv6.addresses': 'Címek',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 kliens',
    'settings.network.ipv6.notInstalled': 'Nincs telepítve',
    'settings.network.ipv6.manualSettings': 'Kézi IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-cím',
    'settings.network.ipv6.prefix': 'Előtag',
    'settings.network.ipv6.invalidManual':
      'Adj meg érvényes IPv6-címet, előtagot és útvonalválasztót',
    'settings.network.ipv6.clientMissing':
      'A DHCPv6 kliens nincs telepítve. Először telepítsd a megfelelő raw rendszerfrissítést.',
    'settings.network.ipv6.saved': 'IPv6-beállítások mentve',
    'settings.network.ipv6.saveFailed': 'Nem sikerült menteni az IPv6-beállításokat',
    'settings.network.ipv6.loadFailed': 'Nem sikerült betölteni az IPv6-beállításokat',
    'settings.network.ipv6.unsaved': 'Nem mentett módosítások'
  },
  id: {
    'settings.network.tls.rebootTitle': 'NanoKVM akan dimulai ulang',
    'settings.network.tls.rebootDesc':
      'Perubahan protokol memerlukan mulai ulang perangkat. Browser akan beralih ke alamat baru setelah {{seconds}} detik:',
    'settings.network.tls.rebootOk': 'Terapkan dan mulai ulang',
    'settings.network.tls.rebootCancel': 'Batal',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Konfigurasikan pengalamatan IPv6 untuk antarmuka kabel',
    'settings.network.ipv6.disabled': 'Dinonaktifkan',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manual',
    'settings.network.ipv6.apply': 'Terapkan',
    'settings.network.ipv6.status': 'Status IPv6',
    'settings.network.ipv6.interface': 'Antarmuka',
    'settings.network.ipv6.state': 'Status',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Alamat',
    'settings.network.ipv6.dhcpv6Client': 'Klien DHCPv6',
    'settings.network.ipv6.notInstalled': 'Belum terpasang',
    'settings.network.ipv6.manualSettings': 'IPv6 manual',
    'settings.network.ipv6.ipAddress': 'Alamat IPv6',
    'settings.network.ipv6.prefix': 'Prefiks',
    'settings.network.ipv6.invalidManual': 'Masukkan alamat IPv6, prefiks, dan router yang valid',
    'settings.network.ipv6.clientMissing':
      'Klien DHCPv6 belum terpasang. Pasang pembaruan sistem raw yang sesuai terlebih dahulu.',
    'settings.network.ipv6.saved': 'Pengaturan IPv6 disimpan',
    'settings.network.ipv6.saveFailed': 'Gagal menyimpan pengaturan IPv6',
    'settings.network.ipv6.loadFailed': 'Gagal memuat pengaturan IPv6',
    'settings.network.ipv6.unsaved': 'Perubahan belum disimpan'
  },
  it: {
    'settings.network.tls.rebootTitle': 'NanoKVM verrà riavviato',
    'settings.network.tls.rebootDesc':
      'La modifica del protocollo richiede il riavvio del dispositivo. Il browser passerà al nuovo indirizzo dopo {{seconds}} secondi:',
    'settings.network.tls.rebootOk': 'Applica e riavvia',
    'settings.network.tls.rebootCancel': 'Annulla',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      "Configura l'indirizzamento IPv6 per l'interfaccia cablata",
    'settings.network.ipv6.disabled': 'Disabilitato',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuale',
    'settings.network.ipv6.apply': 'Applica',
    'settings.network.ipv6.status': 'Stato IPv6',
    'settings.network.ipv6.interface': 'Interfaccia',
    'settings.network.ipv6.state': 'Stato',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Indirizzi',
    'settings.network.ipv6.dhcpv6Client': 'Client DHCPv6',
    'settings.network.ipv6.notInstalled': 'Non installato',
    'settings.network.ipv6.manualSettings': 'IPv6 manuale',
    'settings.network.ipv6.ipAddress': 'Indirizzo IPv6',
    'settings.network.ipv6.prefix': 'Prefisso',
    'settings.network.ipv6.invalidManual':
      'Inserisci un indirizzo IPv6, un prefisso e un router validi',
    'settings.network.ipv6.clientMissing':
      "Il client DHCPv6 non è installato. Installa prima l'aggiornamento raw di sistema corrispondente.",
    'settings.network.ipv6.saved': 'Impostazioni IPv6 salvate',
    'settings.network.ipv6.saveFailed': 'Impossibile salvare le impostazioni IPv6',
    'settings.network.ipv6.loadFailed': 'Impossibile caricare le impostazioni IPv6',
    'settings.network.ipv6.unsaved': 'Modifiche non salvate'
  },
  ja: {
    'settings.network.tls.rebootTitle': 'NanoKVM を再起動します',
    'settings.network.tls.rebootDesc':
      'プロトコルの変更にはデバイスの再起動が必要です。{{seconds}} 秒後にブラウザーは新しいアドレスへ切り替わります:',
    'settings.network.tls.rebootOk': '適用して再起動',
    'settings.network.tls.rebootCancel': 'キャンセル',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': '有線インターフェースの IPv6 アドレス設定',
    'settings.network.ipv6.disabled': '無効',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': '手動',
    'settings.network.ipv6.apply': '適用',
    'settings.network.ipv6.status': 'IPv6 ステータス',
    'settings.network.ipv6.interface': 'インターフェース',
    'settings.network.ipv6.state': '状態',
    'settings.network.ipv6.router': 'ルーター',
    'settings.network.ipv6.addresses': 'アドレス',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 クライアント',
    'settings.network.ipv6.notInstalled': '未インストール',
    'settings.network.ipv6.manualSettings': '手動 IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6 アドレス',
    'settings.network.ipv6.prefix': 'プレフィックス',
    'settings.network.ipv6.invalidManual':
      '有効な IPv6 アドレス、プレフィックス、ルーターを入力してください',
    'settings.network.ipv6.clientMissing':
      'DHCPv6 クライアントがインストールされていません。先に対応する raw システムアップデートをインストールしてください。',
    'settings.network.ipv6.saved': 'IPv6 設定を保存しました',
    'settings.network.ipv6.saveFailed': 'IPv6 設定の保存に失敗しました',
    'settings.network.ipv6.loadFailed': 'IPv6 設定の読み込みに失敗しました',
    'settings.network.ipv6.unsaved': '未保存の変更'
  },
  ko: {
    'settings.network.tls.rebootTitle': 'NanoKVM이 재부팅됩니다',
    'settings.network.tls.rebootDesc':
      '프로토콜 변경에는 장치 재부팅이 필요합니다. 브라우저는 {{seconds}}초 후 새 주소로 전환됩니다:',
    'settings.network.tls.rebootOk': '적용 후 재부팅',
    'settings.network.tls.rebootCancel': '취소',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': '유선 인터페이스의 IPv6 주소 설정',
    'settings.network.ipv6.disabled': '비활성화됨',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': '수동',
    'settings.network.ipv6.apply': '적용',
    'settings.network.ipv6.status': 'IPv6 상태',
    'settings.network.ipv6.interface': '인터페이스',
    'settings.network.ipv6.state': '상태',
    'settings.network.ipv6.router': '라우터',
    'settings.network.ipv6.addresses': '주소',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 클라이언트',
    'settings.network.ipv6.notInstalled': '설치되지 않음',
    'settings.network.ipv6.manualSettings': '수동 IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6 주소',
    'settings.network.ipv6.prefix': '프리픽스',
    'settings.network.ipv6.invalidManual': '유효한 IPv6 주소, 프리픽스 및 라우터를 입력하세요',
    'settings.network.ipv6.clientMissing':
      'DHCPv6 클라이언트가 설치되어 있지 않습니다. 먼저 일치하는 raw 시스템 업데이트를 설치하세요.',
    'settings.network.ipv6.saved': 'IPv6 설정이 저장되었습니다',
    'settings.network.ipv6.saveFailed': 'IPv6 설정 저장 실패',
    'settings.network.ipv6.loadFailed': 'IPv6 설정 불러오기 실패',
    'settings.network.ipv6.unsaved': '저장되지 않은 변경 사항'
  },
  nb: {
    'settings.network.tls.rebootTitle': 'NanoKVM starter på nytt',
    'settings.network.tls.rebootDesc':
      'Protokollendringen krever omstart av enheten. Nettleseren bytter til den nye adressen etter {{seconds}} sekunder:',
    'settings.network.tls.rebootOk': 'Bruk og start på nytt',
    'settings.network.tls.rebootCancel': 'Avbryt',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Konfigurer IPv6-adressering for kablet grensesnitt',
    'settings.network.ipv6.disabled': 'Deaktivert',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuelt',
    'settings.network.ipv6.apply': 'Bruk',
    'settings.network.ipv6.status': 'IPv6-status',
    'settings.network.ipv6.interface': 'Grensesnitt',
    'settings.network.ipv6.state': 'Tilstand',
    'settings.network.ipv6.router': 'Ruter',
    'settings.network.ipv6.addresses': 'Adresser',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6-klient',
    'settings.network.ipv6.notInstalled': 'Ikke installert',
    'settings.network.ipv6.manualSettings': 'Manuell IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-adresse',
    'settings.network.ipv6.prefix': 'Prefiks',
    'settings.network.ipv6.invalidManual': 'Angi en gyldig IPv6-adresse, prefiks og ruter',
    'settings.network.ipv6.clientMissing':
      'DHCPv6-klienten er ikke installert. Installer først den matchende raw-systemoppdateringen.',
    'settings.network.ipv6.saved': 'IPv6-innstillinger lagret',
    'settings.network.ipv6.saveFailed': 'Kunne ikke lagre IPv6-innstillinger',
    'settings.network.ipv6.loadFailed': 'Kunne ikke laste IPv6-innstillinger',
    'settings.network.ipv6.unsaved': 'Ulagrede endringer'
  },
  nl: {
    'settings.network.tls.rebootTitle': 'NanoKVM wordt opnieuw opgestart',
    'settings.network.tls.rebootDesc':
      'De protocolwijziging vereist een herstart van het apparaat. De browser schakelt na {{seconds}} seconden over naar het nieuwe adres:',
    'settings.network.tls.rebootOk': 'Toepassen en opnieuw opstarten',
    'settings.network.tls.rebootCancel': 'Annuleren',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      'IPv6-adressering configureren voor de bekabelde interface',
    'settings.network.ipv6.disabled': 'Uitgeschakeld',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Handmatig',
    'settings.network.ipv6.apply': 'Toepassen',
    'settings.network.ipv6.status': 'IPv6-status',
    'settings.network.ipv6.interface': 'Interface',
    'settings.network.ipv6.state': 'Status',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Adressen',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6-client',
    'settings.network.ipv6.notInstalled': 'Niet geïnstalleerd',
    'settings.network.ipv6.manualSettings': 'Handmatige IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-adres',
    'settings.network.ipv6.prefix': 'Prefix',
    'settings.network.ipv6.invalidManual': 'Voer een geldig IPv6-adres, prefix en router in',
    'settings.network.ipv6.clientMissing':
      'De DHCPv6-client is niet geïnstalleerd. Installeer eerst de bijbehorende raw-systeemupdate.',
    'settings.network.ipv6.saved': 'IPv6-instellingen opgeslagen',
    'settings.network.ipv6.saveFailed': 'Opslaan van IPv6-instellingen mislukt',
    'settings.network.ipv6.loadFailed': 'Laden van IPv6-instellingen mislukt',
    'settings.network.ipv6.unsaved': 'Niet-opgeslagen wijzigingen'
  },
  pl: {
    'settings.network.tls.rebootTitle': 'NanoKVM zostanie uruchomiony ponownie',
    'settings.network.tls.rebootDesc':
      'Zmiana protokołu wymaga restartu urządzenia. Przeglądarka przełączy się na nowy adres po {{seconds}} sekundach:',
    'settings.network.tls.rebootOk': 'Zastosuj i uruchom ponownie',
    'settings.network.tls.rebootCancel': 'Anuluj',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Skonfiguruj adresację IPv6 dla interfejsu przewodowego',
    'settings.network.ipv6.disabled': 'Wyłączone',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Ręcznie',
    'settings.network.ipv6.apply': 'Zastosuj',
    'settings.network.ipv6.status': 'Stan IPv6',
    'settings.network.ipv6.interface': 'Interfejs',
    'settings.network.ipv6.state': 'Stan',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Adresy',
    'settings.network.ipv6.dhcpv6Client': 'Klient DHCPv6',
    'settings.network.ipv6.notInstalled': 'Nie zainstalowano',
    'settings.network.ipv6.manualSettings': 'Ręczny IPv6',
    'settings.network.ipv6.ipAddress': 'Adres IPv6',
    'settings.network.ipv6.prefix': 'Prefiks',
    'settings.network.ipv6.invalidManual': 'Wprowadź prawidłowy adres IPv6, prefiks i router',
    'settings.network.ipv6.clientMissing':
      'Klient DHCPv6 nie jest zainstalowany. Najpierw zainstaluj pasującą raw aktualizację systemu.',
    'settings.network.ipv6.saved': 'Ustawienia IPv6 zapisane',
    'settings.network.ipv6.saveFailed': 'Nie udało się zapisać ustawień IPv6',
    'settings.network.ipv6.loadFailed': 'Nie udało się wczytać ustawień IPv6',
    'settings.network.ipv6.unsaved': 'Niezapisane zmiany'
  },
  pt_br: {
    'settings.network.tls.rebootTitle': 'NanoKVM será reiniciado',
    'settings.network.tls.rebootDesc':
      'A alteração do protocolo exige reiniciar o dispositivo. O navegador mudará para o novo endereço após {{seconds}} segundos:',
    'settings.network.tls.rebootOk': 'Aplicar e reiniciar',
    'settings.network.tls.rebootCancel': 'Cancelar',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Configurar endereçamento IPv6 para a interface cabeada',
    'settings.network.ipv6.disabled': 'Desativado',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manual',
    'settings.network.ipv6.apply': 'Aplicar',
    'settings.network.ipv6.status': 'Status IPv6',
    'settings.network.ipv6.interface': 'Interface',
    'settings.network.ipv6.state': 'Estado',
    'settings.network.ipv6.router': 'Roteador',
    'settings.network.ipv6.addresses': 'Enderecos',
    'settings.network.ipv6.dhcpv6Client': 'Cliente DHCPv6',
    'settings.network.ipv6.notInstalled': 'Não instalado',
    'settings.network.ipv6.manualSettings': 'IPv6 manual',
    'settings.network.ipv6.ipAddress': 'Endereço IPv6',
    'settings.network.ipv6.prefix': 'Prefixo',
    'settings.network.ipv6.invalidManual': 'Insira um endereço IPv6, prefixo e roteador válidos',
    'settings.network.ipv6.clientMissing':
      'O cliente DHCPv6 não está instalado. Instale primeiro a atualização raw do sistema correspondente.',
    'settings.network.ipv6.saved': 'Configurações IPv6 salvas',
    'settings.network.ipv6.saveFailed': 'Falha ao salvar as configurações IPv6',
    'settings.network.ipv6.loadFailed': 'Falha ao carregar as configurações IPv6',
    'settings.network.ipv6.unsaved': 'Alterações não salvas'
  },
  se: {
    'settings.network.tls.rebootTitle': 'NanoKVM startar om',
    'settings.network.tls.rebootDesc':
      'Protokolländringen kräver omstart av enheten. Webbläsaren byter till den nya adressen efter {{seconds}} sekunder:',
    'settings.network.tls.rebootOk': 'Verkställ och starta om',
    'settings.network.tls.rebootCancel': 'Avbryt',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description':
      'Konfigurera IPv6-adressering för det trådbundna gränssnittet',
    'settings.network.ipv6.disabled': 'Inaktiverad',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuell',
    'settings.network.ipv6.apply': 'Verkställ',
    'settings.network.ipv6.status': 'IPv6-status',
    'settings.network.ipv6.interface': 'Gränssnitt',
    'settings.network.ipv6.state': 'Tillstånd',
    'settings.network.ipv6.router': 'Router',
    'settings.network.ipv6.addresses': 'Adresser',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6-klient',
    'settings.network.ipv6.notInstalled': 'Inte installerad',
    'settings.network.ipv6.manualSettings': 'Manuell IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6-adress',
    'settings.network.ipv6.prefix': 'Prefix',
    'settings.network.ipv6.invalidManual': 'Ange en giltig IPv6-adress, prefix och router',
    'settings.network.ipv6.clientMissing':
      'DHCPv6-klienten är inte installerad. Installera först den matchande raw-systemuppdateringen.',
    'settings.network.ipv6.saved': 'IPv6-inställningar sparade',
    'settings.network.ipv6.saveFailed': 'Det gick inte att spara IPv6-inställningar',
    'settings.network.ipv6.loadFailed': 'Det gick inte att läsa in IPv6-inställningar',
    'settings.network.ipv6.unsaved': 'Osparade ändringar'
  },
  th: {
    'settings.network.tls.rebootTitle': 'NanoKVM จะรีบูต',
    'settings.network.tls.rebootDesc':
      'การเปลี่ยนโปรโตคอลต้องรีบูตอุปกรณ์ เบราว์เซอร์จะเปลี่ยนไปยังที่อยู่ใหม่หลังจาก {{seconds}} วินาที:',
    'settings.network.tls.rebootOk': 'ใช้และรีบูต',
    'settings.network.tls.rebootCancel': 'ยกเลิก',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'กำหนดค่าการกำหนดที่อยู่ IPv6 สำหรับอินเทอร์เฟซแบบใช้สาย',
    'settings.network.ipv6.disabled': 'ปิดใช้งาน',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'ด้วยตนเอง',
    'settings.network.ipv6.apply': 'ใช้',
    'settings.network.ipv6.status': 'สถานะ IPv6',
    'settings.network.ipv6.interface': 'อินเทอร์เฟซ',
    'settings.network.ipv6.state': 'สถานะ',
    'settings.network.ipv6.router': 'เราเตอร์',
    'settings.network.ipv6.addresses': 'ที่อยู่',
    'settings.network.ipv6.dhcpv6Client': 'ไคลเอนต์ DHCPv6',
    'settings.network.ipv6.notInstalled': 'ไม่ได้ติดตั้ง',
    'settings.network.ipv6.manualSettings': 'IPv6 ด้วยตนเอง',
    'settings.network.ipv6.ipAddress': 'ที่อยู่ IPv6',
    'settings.network.ipv6.prefix': 'พรีฟิกซ์',
    'settings.network.ipv6.invalidManual': 'โปรดป้อนที่อยู่ IPv6, พรีฟิกซ์ และเราเตอร์ที่ถูกต้อง',
    'settings.network.ipv6.clientMissing':
      'ยังไม่ได้ติดตั้งไคลเอนต์ DHCPv6 โปรดติดตั้งการอัปเดตระบบ raw ที่ตรงกันก่อน',
    'settings.network.ipv6.saved': 'บันทึกการตั้งค่า IPv6 แล้ว',
    'settings.network.ipv6.saveFailed': 'บันทึกการตั้งค่า IPv6 ไม่สำเร็จ',
    'settings.network.ipv6.loadFailed': 'โหลดการตั้งค่า IPv6 ไม่สำเร็จ',
    'settings.network.ipv6.unsaved': 'การเปลี่ยนแปลงที่ยังไม่ได้บันทึก'
  },
  tr: {
    'settings.network.tls.rebootTitle': 'NanoKVM yeniden başlatılacak',
    'settings.network.tls.rebootDesc':
      'Protokol değişikliği cihazın yeniden başlatılmasını gerektirir. Tarayıcı {{seconds}} saniye sonra yeni adrese geçecek:',
    'settings.network.tls.rebootOk': 'Uygula ve yeniden başlat',
    'settings.network.tls.rebootCancel': 'İptal',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Kablolu arayüz için IPv6 adreslemesini yapılandır',
    'settings.network.ipv6.disabled': 'Devre dışı',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Manuel',
    'settings.network.ipv6.apply': 'Uygula',
    'settings.network.ipv6.status': 'IPv6 Durumu',
    'settings.network.ipv6.interface': 'Arayüz',
    'settings.network.ipv6.state': 'Durum',
    'settings.network.ipv6.router': 'Yönlendirici',
    'settings.network.ipv6.addresses': 'Adresler',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 İstemcisi',
    'settings.network.ipv6.notInstalled': 'Kurulu değil',
    'settings.network.ipv6.manualSettings': 'Manuel IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6 Adresi',
    'settings.network.ipv6.prefix': 'Ön ek',
    'settings.network.ipv6.invalidManual': 'Geçerli bir IPv6 adresi, ön ek ve yönlendirici girin',
    'settings.network.ipv6.clientMissing':
      'DHCPv6 istemcisi kurulu değil. Önce eşleşen raw sistem güncellemesini kurun.',
    'settings.network.ipv6.saved': 'IPv6 ayarları kaydedildi',
    'settings.network.ipv6.saveFailed': 'IPv6 ayarları kaydedilemedi',
    'settings.network.ipv6.loadFailed': 'IPv6 ayarları yüklenemedi',
    'settings.network.ipv6.unsaved': 'Kaydedilmemiş değişiklikler'
  },
  uk: {
    'settings.network.tls.rebootTitle': 'NanoKVM перезавантажиться',
    'settings.network.tls.rebootDesc':
      'Зміна протоколу потребує перезавантаження пристрою. Браузер перейде на нову адресу через {{seconds}} секунд:',
    'settings.network.tls.rebootOk': 'Застосувати й перезавантажити',
    'settings.network.tls.rebootCancel': 'Скасувати',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Налаштувати IPv6-адресацію для дротового інтерфейсу',
    'settings.network.ipv6.disabled': 'Вимкнено',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Вручну',
    'settings.network.ipv6.apply': 'Застосувати',
    'settings.network.ipv6.status': 'Стан IPv6',
    'settings.network.ipv6.interface': 'Інтерфейс',
    'settings.network.ipv6.state': 'Стан',
    'settings.network.ipv6.router': 'Маршрутизатор',
    'settings.network.ipv6.addresses': 'Адреси',
    'settings.network.ipv6.dhcpv6Client': 'Клієнт DHCPv6',
    'settings.network.ipv6.notInstalled': 'Не встановлено',
    'settings.network.ipv6.manualSettings': 'IPv6 вручну',
    'settings.network.ipv6.ipAddress': 'IPv6-адреса',
    'settings.network.ipv6.prefix': 'Префікс',
    'settings.network.ipv6.invalidManual': 'Введіть дійсну IPv6-адресу, префікс і маршрутизатор',
    'settings.network.ipv6.clientMissing':
      'Клієнт DHCPv6 не встановлено. Спочатку встановіть відповідне raw-оновлення системи.',
    'settings.network.ipv6.saved': 'Налаштування IPv6 збережено',
    'settings.network.ipv6.saveFailed': 'Не вдалося зберегти налаштування IPv6',
    'settings.network.ipv6.loadFailed': 'Не вдалося завантажити налаштування IPv6',
    'settings.network.ipv6.unsaved': 'Незбережені зміни'
  },
  vi: {
    'settings.network.tls.rebootTitle': 'NanoKVM sẽ khởi động lại',
    'settings.network.tls.rebootDesc':
      'Việc thay đổi giao thức yêu cầu khởi động lại thiết bị. Trình duyệt sẽ chuyển sang địa chỉ mới sau {{seconds}} giây:',
    'settings.network.tls.rebootOk': 'Áp dụng và khởi động lại',
    'settings.network.tls.rebootCancel': 'Hủy',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': 'Cấu hình địa chỉ IPv6 cho giao diện có dây',
    'settings.network.ipv6.disabled': 'Đã tắt',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': 'Thủ công',
    'settings.network.ipv6.apply': 'Áp dụng',
    'settings.network.ipv6.status': 'Trạng thái IPv6',
    'settings.network.ipv6.interface': 'Giao diện',
    'settings.network.ipv6.state': 'Trạng thái',
    'settings.network.ipv6.router': 'Bộ định tuyến',
    'settings.network.ipv6.addresses': 'Địa chỉ',
    'settings.network.ipv6.dhcpv6Client': 'Máy khách DHCPv6',
    'settings.network.ipv6.notInstalled': 'Chưa cài đặt',
    'settings.network.ipv6.manualSettings': 'IPv6 thủ công',
    'settings.network.ipv6.ipAddress': 'Địa chỉ IPv6',
    'settings.network.ipv6.prefix': 'Tiền tố',
    'settings.network.ipv6.invalidManual': 'Nhập địa chỉ IPv6, tiền tố và bộ định tuyến hợp lệ',
    'settings.network.ipv6.clientMissing':
      'Máy khách DHCPv6 chưa được cài đặt. Hãy cài đặt bản cập nhật hệ thống raw phù hợp trước.',
    'settings.network.ipv6.saved': 'Đã lưu cài đặt IPv6',
    'settings.network.ipv6.saveFailed': 'Không thể lưu cài đặt IPv6',
    'settings.network.ipv6.loadFailed': 'Không thể tải cài đặt IPv6',
    'settings.network.ipv6.unsaved': 'Thay đổi chưa lưu'
  },
  zh: {
    'settings.network.tls.rebootTitle': 'NanoKVM 将重启',
    'settings.network.tls.rebootDesc':
      '协议更改需要设备重启。浏览器将在 {{seconds}} 秒后切换到新地址：',
    'settings.network.tls.rebootOk': '应用并重启',
    'settings.network.tls.rebootCancel': '取消',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': '为有线接口配置 IPv6 地址',
    'settings.network.ipv6.disabled': '已禁用',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': '手动',
    'settings.network.ipv6.apply': '应用',
    'settings.network.ipv6.status': 'IPv6 状态',
    'settings.network.ipv6.interface': '接口',
    'settings.network.ipv6.state': '状态',
    'settings.network.ipv6.router': '路由器',
    'settings.network.ipv6.addresses': '地址',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 客户端',
    'settings.network.ipv6.notInstalled': '未安装',
    'settings.network.ipv6.manualSettings': '手动 IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6 地址',
    'settings.network.ipv6.prefix': '前缀',
    'settings.network.ipv6.invalidManual': '请输入有效的 IPv6 地址、前缀和路由器',
    'settings.network.ipv6.clientMissing': '未安装 DHCPv6 客户端。请先安装匹配的 raw 系统更新。',
    'settings.network.ipv6.saved': 'IPv6 设置已保存',
    'settings.network.ipv6.saveFailed': '保存 IPv6 设置失败',
    'settings.network.ipv6.loadFailed': '加载 IPv6 设置失败',
    'settings.network.ipv6.unsaved': '未保存的更改'
  },
  zh_tw: {
    'settings.network.tls.rebootTitle': 'NanoKVM 將重新啟動',
    'settings.network.tls.rebootDesc':
      '通訊協定變更需要重新啟動裝置。瀏覽器將在 {{seconds}} 秒後切換到新位址：',
    'settings.network.tls.rebootOk': '套用並重新啟動',
    'settings.network.tls.rebootCancel': '取消',
    'settings.network.ipv6.title': 'IPv6',
    'settings.network.ipv6.description': '為有線介面設定 IPv6 位址',
    'settings.network.ipv6.disabled': '已停用',
    'settings.network.ipv6.slaac': 'SLAAC',
    'settings.network.ipv6.dhcpv6': 'DHCPv6',
    'settings.network.ipv6.manual': '手動',
    'settings.network.ipv6.apply': '套用',
    'settings.network.ipv6.status': 'IPv6 狀態',
    'settings.network.ipv6.interface': '介面',
    'settings.network.ipv6.state': '狀態',
    'settings.network.ipv6.router': '路由器',
    'settings.network.ipv6.addresses': '位址',
    'settings.network.ipv6.dhcpv6Client': 'DHCPv6 客戶端',
    'settings.network.ipv6.notInstalled': '未安裝',
    'settings.network.ipv6.manualSettings': '手動 IPv6',
    'settings.network.ipv6.ipAddress': 'IPv6 位址',
    'settings.network.ipv6.prefix': '前綴',
    'settings.network.ipv6.invalidManual': '請輸入有效的 IPv6 位址、前綴和路由器',
    'settings.network.ipv6.clientMissing': '尚未安裝 DHCPv6 客戶端。請先安裝相符的 raw 系統更新。',
    'settings.network.ipv6.saved': 'IPv6 設定已儲存',
    'settings.network.ipv6.saveFailed': '儲存 IPv6 設定失敗',
    'settings.network.ipv6.loadFailed': '載入 IPv6 設定失敗',
    'settings.network.ipv6.unsaved': '未儲存的變更'
  }
};

function getDeep(target: Record<string, unknown>, path: string) {
  return path.split('.').reduce<unknown>((value, key) => {
    if (!value || typeof value !== 'object') return undefined;
    return (value as Record<string, unknown>)[key];
  }, target);
}

function setDeep(target: Record<string, unknown>, path: string, value: string) {
  const parts = path.split('.');
  let current = target;

  for (const part of parts.slice(0, -1)) {
    const next = current[part];
    if (!next || typeof next !== 'object') {
      current[part] = {};
    }
    current = current[part] as Record<string, unknown>;
  }

  const leaf = parts[parts.length - 1];
  if (typeof getDeep(target, path) !== 'string') {
    current[leaf] = value;
  }
}

export function applyLocaleExtras(language: string, resource: ResourceLanguage) {
  const key = languageAliases[language] || language;
  const extras = networkExtras[key];
  if (!extras) return;

  const typedResource = resource as { translation?: Record<string, unknown> };
  typedResource.translation ??= {};

  for (const [path, value] of Object.entries(extras)) {
    setDeep(typedResource.translation, path, value);
  }
}
