# Сборка

Поддерживаемый путь — Linux x86_64 или WSL2 Debian/Ubuntu. Для сборки с нуля
нужно примерно 8 ГБ свободного места плюс Android SDK. Образ boot и IDA не нужны.

## 1. Зависимости

```bash
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex libssl-dev libelf-dev \
    python3 curl git openjdk-21-jdk
git clone https://github.com/shellovxx/DFRoot-OnePlus9RT.git
cd DFRoot-OnePlus9RT
```

Установите Android SDK command-line tools. Затем:

```bash
export ANDROID_HOME="$HOME/Android/Sdk" # ваш путь к SDK
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
sdkmanager --licenses
sdkmanager 'platforms;android-37.0' 'build-tools;36.1.0' \
    'ndk;28.2.13676358' 'cmake;3.22.1'
```

Gradle wrapper скачает Gradle 9.7.1. Используется AGP 9.4.0 и JDK 21.
Пакет платформы API 37 называется `platforms;android-37.0`.
Если в вашем дистрибутиве нет openjdk-21-jdk, установите JDK 21 отдельно.

## 2. Оба модуля из исходников

```bash
bash scripts/build-modules.sh
```

Скрипт скачивает OnePlus kernel commit
`21e927b4f4c13414a8bfc8d9b8ed20a1cdc2efa0` и Android clang r383902b1,
проверяет SHA256 из `upstream.lock.json`, готовит дерево и собирает оба `.ko`.
KernelSU уже включён в исходники проекта; отдельный clone Manager не нужен.
Версия kernel-компонента зафиксирована как 32680, UAPI 5.

Кэш по умолчанию: `~/.cache/dfroot-oneplus9rt`. Его можно изменить:

```bash
export DFROOT_BUILD_ROOT="$HOME/build/dfroot-oneplus9rt"
bash scripts/build-modules.sh
```

Публичные исходники OnePlus не содержат части vendor/oplus. Сборка создаёт
минимальные недостающие Kconfig-файлы и декларацию заголовка для внешних
модулей. Она не предназначена для сборки полного ядра или прошивки boot.
Конфигурация и `Module.symvers` соответствуют проверенному vendor-ядру.
Одного совпадения версии 5.4 недостаточно для совместимости.

Обязательные проверки: ABI структур при компиляции, CFI, точный vermagic,
экспорты и CRC импортируемых символов. При ошибке сборка останавливается.
Результат находится в `out/modules/` и автоматически копируется в Android app:

- `app/src/main/jni/ko/dfroot-android13-5.4.ko` — загрузочный модуль;
- `app/src/main/assets/kernelsu.ko` — KernelSU LKM.

## 3. Debug APK

```bash
bash scripts/build-apk.sh debug
```

Результат: `out/debug/`. Debug APK подписан стандартным Android debug key.
Он не является опубликованным release APK.

## 4. Подписанный release APK

Создайте собственный постоянный ключ за пределами репозитория:

```bash
mkdir -p "$HOME/.config/dfroot-oneplus9rt"
keytool -genkeypair -storetype JKS \
    -keystore "$HOME/.config/dfroot-oneplus9rt/release.jks" \
    -alias oneplus9rt -keyalg RSA -keysize 3072 -validity 10000 \
    -dname 'CN=DFRoot OnePlus 9RT'
cp signing.properties.example signing.properties
```

Заполните все четыре поля в `signing.properties`: абсолютный путь к ключу,
пароль хранилища, alias и пароль ключа. Этот файл исключён из Git. Сохраните
резервную копию ключа и паролей: обновление установленного APK требует той же
подписи. Собственная подпись отличается от подписи официального релиза порта.

```bash
bash scripts/build-apk.sh release
# либо весь цикл сразу:
make release
```

Release APK: `out/release/DFRoot-OnePlus9RT_4.6-op9rt.1.apk` и `SHA256SUMS`.
Release не debuggable, с R8/resource shrinking; сборка без настроенной подписи
запрещена. Проверить подпись можно через SDK:

```bash
"$ANDROID_HOME/build-tools/36.1.0/apksigner" verify --verbose --print-certs \
    out/release/DFRoot-OnePlus9RT_4.6-op9rt.1.apk
```

## Windows + WSL

Модули собираются в WSL теми же командами. Для скорости предпочтителен clone
в файловой системе Linux. Если Android SDK установлен в Windows, после сборки
модулей создайте локальный `local.properties` с `sdk.dir` для Windows, задайте
`JAVA_HOME` на Windows JDK 21 и выполните из PowerShell:

```powershell
.\gradlew.bat :app:assembleRelease --console=plain
```

Укажите Windows-путь к keystore в локальном `signing.properties` (разделители
`/` удобнее). APK будет в `app/build/outputs/apk/release/`.

## CI и публикация

GitHub Actions собирает оба модуля и debug APK из исходников. Это проверка
сборки; Actions не проверяет загрузку на реальном телефоне и не публикует
непроверенные APK как стабильные релизы. Подписанный APK после проверки на
устройстве размещается в GitHub Releases вместе с SHA256 и описанием проверки.
