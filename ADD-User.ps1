Write-Host "Проверка наличия прав Администратора..." -ForegroundColor Yellow;
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
[Security.Principal.WindowsBuiltInRole] "Administrator")) {
Write-Host "Права Администратора не были обнаружены, перезапустите скрипт с правами Администратора" -ForegroundColor Yellow -NoNewline;
Break
}
else {
Write-Host "Права Администратора обнаружены, продолжаем выполнение скрипта" -ForegroundColor Yellow;
}
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
#---------------#
Write-Host "Поиск сервера Active Directory в локальной сети..."
[string]$DCServerName = (Get-ADDomainController -Discover -NextClosestSite).HostName
Write-Host "Active Directory установлен на сервере - $DCServerName"
Write-Host ""
#---------------#
Write-Host "Поиск доменного имени в локальной сети..."
[string]$Domain = (Get-ADDomain).DNSRoot
Write-Host "Доменное имя найдено: $Domain"
Write-Host ""
#---------------#
Write-Host "Поиск адресса подключения к серверу, на котором установлена роль терминала"
[string]$fullAddress = (Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\cimv2\terminalservices).__SERVER
Write-Host "The address of the Terminal Server is: $fullAddress"
Write-Host ""
#---------------#
Write-Host "Searching for the external IP address of the gateway..."
[string]$gatewayIP = Invoke-RestMethod "https://api.ipify.org?format=text"
Write-Host "External IP address of the gateway: $gatewayIP"
$gatewayName = (Resolve-DnsName -Name $gatewayIP -ErrorAction SilentlyContinue).NameHost
if ($gatewayName) {
    Write-Host "DNS name of the gateway: $gatewayName"
} else {
    Write-Host "Failed to resolve DNS name for the gateway."
    $userChoice = Read-Host "Do you want to enter a DNS name for the gateway manually? (y/n)"
    if ($userChoice.ToLower() -eq "y") {
        $userInput = Read-Host "Enter the DNS name for the gateway:"
        $gatewayName = $userInput
    } else {
        $gatewayName = $gatewayIP
    }
}
Write-Host "Gateway address: $gatewayName"
Write-Host ""
#---------------#
$workspaceID = $fullAddress
$mode = "UseSameCredsForGateway"
#---------------#
Write-Host "Идёт поиск всех OU в " $DCServerName
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -AutoSize
$ID = ''
while ($ID -eq '') {
    $OUName = Read-Host "Введите название OU в которую будем добавлять пользователей"
    if ($OUName.Trim() -eq '') {
        Write-Host "Вы ничего не ввели, попробуйте ещё раз"
		Write-Host ""
    }
    else {
        $OU = Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'"
        if ($OU -ne $null) {
            $ID = $OUName
        }
        else {
            Write-Host "Введено некорректное название OU, попробуйте ещё раз"
			Write-Host ""
        }
    }
}
#---------------#
Write-Host ""
Write-Host "Идёт поиск всех групп в " $DCServerName
Get-ADGroup -Filter {GroupScope -eq "Global"} -Properties SamAccountName, GroupScope | Format-Table SamAccountName, GroupScope
$groupExists = $false
while (!$groupExists) {
  [string]$GroupAD = Read-Host "Введите название группы, в которую нужно добавить пользователей"
  if ([string]::IsNullOrEmpty($GroupAD)) {
    Write-Host "Ошибка: Название группы не может быть пустым. Попробуйте ещё раз."
	Write-Host ""
  } elseif (Get-ADGroup -Filter { SamAccountName -eq $GroupAD }) {
    $groupExists = $true
  } else {
    Write-Host "Группа $GroupAD не найдена в Active Directory. Попробуйте ещё раз."
	Write-Host ""
  }
}
#---------------#
$pattern = "^[a-zA-Z0-9_-]+$"
do {
    [string]$UserName = Read-Host "Введите значение шаблона для именования учётных записей, например User_id666"
    if ([string]::IsNullOrEmpty($UserName)) {
        Write-Host "Ошибка: значение шаблона не может быть пустым."
		Write-Host ""
    }
    elseif ($UserName -notmatch $pattern -or $UserName.Length -gt 20) {
        Write-Host "Ошибка: значение шаблона не соответствует требованиям."
        Write-Host "Требования для шаблона:"
        Write-Host "- Используйте латинские буквы, цифры, подчеркивания и дефисы."
        Write-Host "- Длина шаблона не должна превышать 20 символов."
		Write-Host ""
    }
} until ($UserName -match $pattern -and $UserName.Length -le 20)
Write-Host "Вы выбрали шаблон $UserName для именования учётных записей."
Write-Host ""
#---------------#
Write-Host "Какое кол-во пользователей будем создавать?"
do {
    $Count = Read-Host "Введите значение"
    if (-not [string]::IsNullOrEmpty($Count) -and [int]::TryParse($Count, [ref]$null)) {
        break
    }
    Write-Host "Пожалуйста, введите числовое значение."
	Write-Host ""
} while ($true)
#---------------#

$OUClient = Get-ADObject -LDAPFilter "OU=$ID"
$ADPath = $OUClient.DistinguishedName

if ([string]::IsNullOrEmpty($ADPath)) {
    Write-Host "ADPAth не найден!!" -ForegroundColor Red
    while (!$ADPath) {
        $ADPath = $OUClient.DistinguishedName
    }
}

$Step = 1
$Counter = 0
$Desktop = [System.Environment]::GetFolderPath('Desktop')
$NFolder = $Desktop + '\' + $id
New-Item -ItemType Directory -Path $NFolder -ErrorAction SilentlyContinue

$Date = '(' + (Get-Date).ToString('dd-MM-yyyy - HHч-mmм-ssс') + ')'
$LogPath = $NFolder + '\' + $Date + ' ' + $UserName + '.txt'
Add-Content -Path $LogPath -Value 'Login Name - Password'

do {
    $UserID = $UserName + "_" + $Step
    $Exist = Get-ADUser -Filter {Name -eq $UserID} -SearchBase $OUClient -ErrorAction SilentlyContinue

    if ($Exist) {
        $Step++
    } else {
        $Login = $UserName + "_" + $Step
        $Password = (Get-Random -Count 7 -Input (48..57 + 65..90 + 97..122) | % {[char]$_}) -join ''
		$rand = Get-Random -Count 1 -Input (0..9)
		$rand2 = Get-Random -Count 1 -Input ('a','b','v','C','R','X','T','t','e','y','Y','U','u','A','q','Q','w','W','E','p','P')
		$rand3 = Get-Random -Count 1 -Input ('!','@','#','$','%','^','&','*','(',')','-','_','=')
		$Password = "$rand2$Password$rand$rand3$rand"

        $NewUser = New-ADUser -Name $Login -Server $DCServerName -SamAccountName $Login -UserPrincipalName $Login -OtherName $Login -GivenName $Login -Surname $Login -DisplayName $Login -Path $ADPath -Country "RU" -AccountPassword (ConvertTo-SecureString -AsPlainText $password -Force) -CannotChangePassword $false -ChangePasswordAtLogon $False -Enabled $true -PasswordNeverExpires $true -passthru
        Add-ADGroupMember -Identity $GroupAD -Members $Login -Server $DCServerName
        New-Item -Path $Desktop -ItemType Directory -ErrorAction SilentlyContinue

        $Step++
        $Counter++

        Write-Host "Пользователь $Login успешно создан. Для него сгенерирован пароль - $password" -ForegroundColor green
        Add-Content -Path $LogPath -Value "$Login - $password"
		$RdpFile = $NFolder + $ClientID + "\" + $Login + ".rdp"
			#Write-Output 
			"screen mode id:i:2
			use multimon:i:0
			desktopwidth:i:1920
			desktopheight:i:1080
			session bpp:i:32
			winposstr:s:0,1,1920,0,3856,1079
			compression:i:1
			keyboardhook:i:2
			audiocapturemode:i:0
			videoplaybackmode:i:1
			connection type:i:7
			networkautodetect:i:1
			bandwidthautodetect:i:1
			displayconnectionbar:i:1
			enableworkspacereconnect:i:0
			disable wallpaper:i:0
			allow font smoothing:i:0
			allow desktop composition:i:0
			disable full window drag:i:1
			disable menu anims:i:1
			disable themes:i:0
			disable cursor setting:i:0
			bitmapcachepersistenable:i:1
			full address:s:$($fullAddress)
			audiomode:i:0
			redirectprinters:i:1
			redirectcomports:i:0
			redirectsmartcards:i:1
			redirectclipboard:i:1
			redirectposdevices:i:0
			autoreconnection enabled:i:1
			authentication level:i:2
			prompt for credentials:i:0
			negotiate security layer:i:1
			remoteapplicationmode:i:0
			alternate shell:s:
			shell working directory:s:
			gatewayusagemethod:i:1
			redirectwebauthn:i:1
			enablerdsaadauth:i:1
			camerastoredirect:s:*
			devicestoredirect:s:*
			drivestoredirect:s:*
			gatewayprofileusagemethod:i:1
			gatewaybrokeringtype:i:0
			use redirection server name:i:0
			rdgiskdcproxy:i:0
			kdcproxyname:s:
			gatewaycredentialssource:i:4
			promptcredentialonce:i:1
			gatewayhostname:s:$($gateway)
			workspace id:s:$($workspaceID)
			username:s:$($Login)@$($domain)" | Out-File -FilePath "$RdpFile" -Encoding utf8	
    }
} until ($Counter -eq $count)
