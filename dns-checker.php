<?php
declare(strict_types=1);

/**
 * DNS Mail Checker — API JSON back-end
 *
 * Ce fichier est l'unique point d'entrée côté serveur de l'outil d'audit e-mail.
 * Il reçoit les requêtes HTTP POST envoyées par le widget Elementor (bloc html.html),
 * interroge les DNS publics du domaine saisi et retourne un rapport JSON structuré.
 *
 * Protocoles analysés :
 *   - MX  : présence des serveurs de réception, Reverse DNS (PTR), FCrDNS croisé
 *   - SPF : analyse récursive RFC 7208, compteur de lookups, include:, +all, ptr
 *   - DKIM: test de 18 sélecteurs courants, taille de clé RSA, révocation
 *   - DMARC : tags complets, héritage domaine parent, rapports externes RFC 7489
 *   - BIMI : logo SVG, certificat VMC, compatibilité DMARC
 *   - MTA-STS : DNS TXT + vérification HTTPS du fichier de politique
 *   - TLS-RPT : enregistrement DNS, destination des rapports
 *
 * Contraintes techniques :
 *   - Zéro dépendance externe (pas de Composer, pas de framework)
 *   - Zéro base de données (aucune persistance)
 *   - Compatible PHP 7.4, 8.0, 8.1, 8.2, 8.3, 8.5+
 *   - Hébergement mutualisé classique (OVH, o2switch, cPanel, Cloudways…)
 *
 * Sécurité :
 *   - Méthode POST obligatoire (CSRF naturel)
 *   - Honeypot anti-bot (champ invisible dans le formulaire)
 *   - Validation et assainissement strict du domaine et du sélecteur DKIM
 *
 * @author  thierrylaval.dev
 * @version 2.0
 */

// Force le type JSON avec encodage UTF-8 et désactive tout cache navigateur/proxy.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

/**
 * Nombre maximum de requêtes DNS autorisées dans une chaîne SPF (RFC 7208 §4.6.4).
 * Au-delà de 10, les serveurs récepteurs doivent retourner une erreur PermError.
 */
const MAX_SPF_DNS_LOOKUPS = 10;

/**
 * Délai maximum (en secondes) pour les requêtes HTTP cURL (vérification MTA-STS).
 * Valeur courte pour ne pas bloquer la réponse JSON de l'outil.
 */
const HTTP_TIMEOUT = 5;

/**
 * Liste des sélecteurs DKIM testés automatiquement quand l'utilisateur n'en fournit pas.
 * Ces sélecteurs sont utilisés par les fournisseurs de messagerie les plus courants
 * (Google, Microsoft, Mailjet, Brevo, Proton, Zoho, SendGrid, Mandrill, etc.).
 * Note : il est impossible de découvrir un sélecteur arbitraire via DNS public —
 * seule une liste prédéfinie peut être testée de cette façon.
 */
const DEFAULT_DKIM_SELECTORS = [
    'google', 'selector1', 'selector2', 'default', 'dkim',
    'k1', 'k2', 'mail', 'smtp', 'email', 's1', 's2',
    'mandrill', 'sendgrid', 'protonmail', 'zoho', 'key1', '20230601'
];

/**
 * Envoie la réponse JSON finale au client et arrête l'exécution PHP.
 *
 * Cette fonction vide tous les tampons de sortie ouverts (ob_start) avant d'écrire
 * le JSON, pour éviter tout contenu parasite (espaces, messages d'avertissement PHP)
 * qui corromprait le JSON et bloquerait le JavaScript côté client.
 *
 * @param array $data     Données à sérialiser en JSON.
 * @param int   $httpCode Code HTTP à retourner (200, 400, 405…).
 * @return never          La fonction ne retourne jamais : elle appelle exit.
 */
function response(array $data, int $httpCode = 200): never
{
    // Vide tous les tampons de sortie ouverts pour garantir un JSON propre.
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($httpCode);
    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_PRETTY_PRINT
    );
    exit;
}


/**
 * SÉCURITÉ — Vérification de la méthode HTTP
 *
 * L'outil n'accepte que les requêtes POST, ce qui empêche :
 *   - Les appels directs via navigateur (GET) qui afficheraient une page vide ou une erreur
 *   - Les tentatives de lecture de la réponse depuis un autre domaine (CSRF simple)
 */
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    response([
        'success' => false,
        'error'   => 'Méthode non autorisée.'
    ], 405);
}

/**
 * SÉCURITÉ — Honeypot anti-bot
 *
 * Un champ masqué (invisible via CSS) est présent dans le formulaire HTML :
 *   - Les humains ne le remplissent jamais car ils ne le voient pas.
 *   - Les robots qui remplissent tous les champs automatiquement le renseignent.
 * Si ce champ contient n'importe quelle valeur, la requête est rejetée immédiatement.
 * Deux noms de champs sont acceptés pour plus de robustesse.
 */
$honeypot = trim((string)($_POST['dmc_hp'] ?? $_POST['website_url_hp'] ?? ''));
if ($honeypot !== '') {
    response([
        'success' => false,
        'error'   => 'Requête invalide.'
    ], 400);
}

// Récupération et nettoyage brut des deux paramètres POST attendus.
$domain   = strtolower(trim((string)($_POST['domain'] ?? '')));
$selector = trim((string)($_POST['selector'] ?? ''));

// Rejet immédiat si le domaine est vide.
if ($domain === '') {
    response([
        'success' => false,
        'error'   => 'Veuillez saisir un domaine.'
    ], 400);
}

/**
 * VALIDATION — Accepte une adresse email complète en entrée.
 *
 * Si l'utilisateur saisit "contact@exemple.fr" au lieu de "exemple.fr",
 * on extrait automatiquement la partie après le @.
 */
if (filter_var($domain, FILTER_VALIDATE_EMAIL)) {
    $domain = substr(strrchr($domain, '@'), 1);
}

/**
 * VALIDATION — Normalisation du domaine saisi.
 *
 * Supprime successivement :
 *   - Le protocole  : "https://exemple.fr" → "exemple.fr"
 *   - Le chemin     : "exemple.fr/page"    → "exemple.fr"
 *   - Le port       : "exemple.fr:8080"    → "exemple.fr"
 *   - Les espaces et points de bord        → "exemple.fr"
 */
$domain = preg_replace('#^https?://#i', '', $domain);
$domain = preg_replace('#/.*$#', '', $domain);
$domain = preg_replace('#:\d+$#', '', $domain);
$domain = trim($domain, " \t\n\r\0\x0B.");

/**
 * VALIDATION — Support des noms de domaine internationalisés (IDN / IDNA).
 *
 * Convertit les domaines avec accents ou caractères Unicode en notation ASCII compatible
 * (Punycode). Ex : "académie.fr" → "xn--acadmie-bua.fr"
 * Nécessite l'extension PHP intl (activée par défaut sur la plupart des hébergeurs).
 */
if (function_exists('idn_to_ascii')) {
    $idn = @idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    if ($idn !== false && $idn !== '') {
        $domain = $idn;
    }
}

/**
 * VALIDATION — Vérification finale du format du domaine.
 *
 * Vérifie que le domaine :
 *   - Ne dépasse pas 253 caractères (limite DNS RFC 1035)
 *   - Correspond au format standard : lettres, chiffres, tirets, points, TLD 2-63 caractères
 * Un domaine invalide (ex : "pas-un-domaine", "123", ".fr") est rejeté.
 */
if (
    strlen($domain) > 253 ||
    !preg_match(
        '/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i',
        $domain
    )
) {
    response([
        'success' => false,
        'error'   => 'Le domaine saisi n’est pas valide.'
    ], 400);
}

/**
 * VALIDATION — Vérification du sélecteur DKIM (si fourni).
 *
 * Les sélecteurs DKIM ne peuvent contenir que des lettres, chiffres, points et tirets.
 * Toute injection de caractères spéciaux est rejetée.
 */
if (
    $selector !== '' &&
    !preg_match('/^[a-zA-Z0-9._-]+$/', $selector)
) {
    response([
        'success' => false,
        'error'   => 'Le sélecteur DKIM n’est pas valide.'
    ], 400);
}


/**
 * Interroge le DNS et retourne les enregistrements d'un type donné pour un hôte.
 *
 * Encapsule dns_get_record() avec suppression des erreurs PHP (@) car la fonction
 * retourne false (et peut émettre un warning) si l'hôte n'existe pas dans le DNS.
 * Garantit toujours un tableau en retour, même vide.
 *
 * @param string $host Nom d'hôte DNS à interroger (ex: "exemple.fr", "_dmarc.exemple.fr").
 * @param int    $type Type d'enregistrement DNS : DNS_TXT, DNS_MX, DNS_A, DNS_AAAA…
 * @return array       Tableau des enregistrements trouvés, ou tableau vide.
 */
function dnsRecords(string $host, int $type): array
{
    $records = @dns_get_record($host, $type);
    return is_array($records) ? $records : [];
}

/**
 * Retourne tous les enregistrements TXT d'un hôte sous forme de chaînes simples.
 *
 * Les enregistrements TXT DNS peuvent être fragmentés en plusieurs "chunks" (morceaux)
 * de 255 caractères max par la norme DNS. PHP retourne ces morceaux dans le tableau
 * 'entries'. Cette fonction les concatène pour obtenir la valeur TXT complète.
 * Elle gère aussi l'ancien format où la valeur est directement dans 'txt'.
 *
 * @param string $host Hôte à interroger.
 * @return array       Tableau de chaînes TXT (une entrée par enregistrement TXT).
 */
function txtRecords(string $host): array
{
    $records = dnsRecords($host, DNS_TXT);
    $result  = [];

    foreach ($records as $record) {
        $txt = '';
        if (isset($record['entries']) && is_array($record['entries'])) {
            // Concatène les morceaux de 255 caractères en une seule chaîne.
            $txt = implode('', $record['entries']);
        } elseif (isset($record['txt'])) {
            $txt = (string)$record['txt'];
        }
        $txt = trim($txt);
        if ($txt !== '') {
            $result[] = $txt;
        }
    }

    return $result;
}

/**
 * Retourne les enregistrements MX d'un domaine, triés par priorité croissante.
 *
 * En DNS MX, une priorité plus faible signifie une préférence plus haute.
 * Le serveur MX avec priorité 10 est essayé avant celui avec priorité 20.
 * Le tri est important pour l'affichage et pour la détection du fournisseur.
 *
 * @param string $domain Domaine à interroger.
 * @return array         Tableau d'enregistrements MX triés par priorité.
 */
function mxRecords(string $domain): array
{
    $records = dnsRecords($domain, DNS_MX);

    usort(
        $records,
        static function ($a, $b) {
            return ((int)($a['pri'] ?? 0))
                <=> ((int)($b['pri'] ?? 0));
        }
    );

    return $records;
}

/**
 * Retourne toutes les adresses IP (IPv4 + IPv6) associées à un hôte.
 *
 * Interroge séparément les enregistrements A (IPv4) et AAAA (IPv6).
 * La constante DNS_AAAA n'est pas disponible sur toutes les versions de PHP,
 * d'où la vérification avec defined('DNS_AAAA').
 * Les doublons sont supprimés et les indices réindexés.
 *
 * @param string $host Nom d'hôte à résoudre (ex: "mx1.ovh.net").
 * @return array       Tableau d'adresses IP uniques.
 */
function hostIPs(string $host): array
{
    $ips = [];

    foreach (dnsRecords($host, DNS_A) as $record) {
        if (!empty($record['ip'])) {
            $ips[] = $record['ip'];
        }
    }

    if (defined('DNS_AAAA')) {
        foreach (dnsRecords($host, DNS_AAAA) as $record) {
            if (!empty($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }
    }

    return array_values(array_unique($ips));
}

/**
 * Retourne le nom d'hôte associé à une adresse IP via le DNS inverse (Reverse DNS / PTR).
 *
 * Le Reverse DNS (PTR) permet de vérifier qu'une IP "se présente" bien avec un nom.
 * C'est une mesure anti-spam basique : un serveur sans PTR est souvent rejeté ou
 * mis en spam par les grandes messageries.
 *
 * gethostbyaddr() est utilisé à la place de dns_get_record(DNS_PTR) car il gère
 * automatiquement l'inversion de l'IP (ex: 1.2.3.4 → 4.3.2.1.in-addr.arpa).
 *
 * @param string $ip Adresse IP à résoudre (IPv4 ou IPv6).
 * @return string    Nom d'hôte trouvé, ou chaîne vide si absent/identique à l'IP.
 */
function ptrRecord(string $ip): string
{
    $ptr = @gethostbyaddr($ip);

    // gethostbyaddr() retourne l'IP elle-même si aucun PTR n'est trouvé.
    if (!$ptr || $ptr === $ip) {
        return '';
    }

    return $ptr;
}


/**
 * Retourne tous les enregistrements TXT commençant par "v=spf1" pour un domaine.
 *
 * Un domaine valide ne doit avoir QU'UN SEUL enregistrement SPF (RFC 7208 §3.2).
 * Cette fonction retourne un tableau — si ce tableau contient plus d'un élément,
 * c'est une erreur de configuration (PermError garanti chez les récepteurs).
 *
 * @param string $domain Domaine à interroger.
 * @return array         Tableau des enregistrements SPF trouvés (idéalement 1 seul).
 */
function getSpfRecords(string $domain): array
{
    $result = [];

    foreach (txtRecords($domain) as $txt) {
        if (preg_match('/^v=spf1(?:\s|$)/i', trim($txt))) {
            $result[] = trim($txt);
        }
    }

    return $result;
}

/**
 * Analyse récursive d'un enregistrement SPF selon la RFC 7208.
 *
 * SPF peut contenir des directives "include:" qui pointent vers d'autres SPF,
 * eux-mêmes pouvant contenir d'autres "include:", formant une arborescence.
 * Chaque mécanisme qui génère une requête DNS (a, mx, include:, exists:, ptr)
 * incrémente le compteur $lookups. La RFC 7208 impose une limite stricte de 10.
 *
 * Cette fonction est appelée récursivement sur chaque "include:" rencontré.
 * Elle détecte les boucles d'inclusion et la profondeur excessive (>10 niveaux).
 *
 * Paramètres passés par référence pour accumuler les données sur toute l'arborescence :
 *   &$lookups     : compteur total de requêtes DNS (partagé sur toute la récursion)
 *   &$voidLookups : compteur de requêtes DNS qui n'ont rien retourné (void lookups)
 *   &$visited     : tableau des domaines déjà visités (anti-boucle)
 *   &$tree        : arbre des inclusions pour l'affichage dans l'interface
 *   &$errors      : erreurs bloquantes accumulées
 *   &$warnings    : avertissements non bloquants accumulés
 *
 * @param string $currentDomain Domaine dont on analyse le SPF (pour les messages d'erreur).
 * @param string $record        L'enregistrement SPF brut à analyser (ex: "v=spf1 include:x ~all").
 * @param int    $lookups       Compteur de lookups DNS (passé par référence).
 * @param int    $voidLookups   Compteur de lookups vides (passé par référence).
 * @param array  $visited       Domaines déjà analysés pour détecter les boucles (passé par référence).
 * @param array  $tree          Arbre des inclusions pour visualisation (passé par référence).
 * @param array  $errors        Erreurs bloquantes accumulées (passé par référence).
 * @param array  $warnings      Avertissements non bloquants (passé par référence).
 * @param int    $depth         Profondeur de récursion actuelle (0 = niveau racine).
 * @return array                Mécanismes analysés, directive "all" et "redirect".
 */
function parseSpfRecursive(
    string $currentDomain,
    string $record,
    int &$lookups,
    int &$voidLookups,
    array &$visited,
    array &$tree,
    array &$errors,
    array &$warnings,
    int $depth = 0
): array {
    $parts = preg_split('/\s+/', trim($record));

    $mechanisms = [];
    $all        = null;
    $redirect   = null;

    // Vérifie que l'enregistrement commence bien par "v=spf1".
    if (!$parts || strtolower($parts[0]) !== 'v=spf1') {
        $errors[] = "Le SPF de '$currentDomain' ne commence pas par v=spf1.";
        return [
            'mechanisms' => [],
            'all'        => null,
            'redirect'   => null
        ];
    }

    // Analyse chaque mécanisme SPF (on saute le premier élément "v=spf1").
    foreach (array_slice($parts ?: [], 1) as $part) {
        if ($part === '') {
            continue;
        }

        // Extraction du qualificateur : + (pass), - (fail), ~ (softfail), ? (neutral).
        // Par défaut (sans qualificateur) c'est + (pass).
        $qualifier = '+';
        if (in_array($part[0], ['+', '-', '~', '?'], true)) {
            $qualifier = $part[0];
            $part      = substr($part, 1);
        }

        $lower = strtolower($part);

        // Mécanisme "all" : s'applique à tous les expéditeurs non couverts par les règles précédentes.
        if ($lower === 'all') {
            $all          = $qualifier;
            $mechanisms[] = [
                'name'      => 'all',
                'value'     => '',
                'qualifier' => $qualifier,
                'lookups'   => 0
            ];
            continue;
        }

        // Mécanisme "redirect=" : délègue l'évaluation SPF à un autre domaine.
        // Compte comme 1 lookup DNS. Récurse dans le domaine cible.
        if (strpos($lower, 'redirect=') === 0) {
            $redirect = substr($part, 9);
            $lookups++;
            $mechanisms[] = [
                'name'      => 'redirect',
                'value'     => $redirect,
                'qualifier' => $qualifier,
                'lookups'   => 1
            ];

            $redLower = strtolower($redirect);
            if (isset($visited[$redLower])) {
                // Boucle infinie détectée : le redirect pointe vers un domaine déjà visité.
                $errors[] = "Boucle infinie détectée dans SPF via redirect=$redirect.";
            } elseif ($depth < 10) {
                $visited[$redLower] = true;
                $subRecords = getSpfRecords($redirect);
                if (!empty($subRecords)) {
                    parseSpfRecursive(
                        $redirect,
                        $subRecords[0],
                        $lookups,
                        $voidLookups,
                        $visited,
                        $tree,
                        $errors,
                        $warnings,
                        $depth + 1
                    );
                } else {
                    // La cible du redirect n'a pas de SPF valide : lookup "void".
                    $voidLookups++;
                    $warnings[] = "La redirection redirect=$redirect ne renvoie aucun enregistrement SPF valide.";
                }
            }
            continue;
        }

        $name  = $part;
        $value = '';

        // Séparation nom:valeur (ex: "include:spf.exemple.fr") ou nom=valeur (ex: "exists=%{d}").
        if (strpos($part, ':') !== false) {
            [$name, $value] = explode(':', $part, 2);
        } elseif (strpos($part, '=') !== false) {
            [$name, $value] = explode('=', $part, 2);
        }

        $name = strtolower($name);
        $cost = 0;

        // Ces mécanismes génèrent chacun une requête DNS → ils incrémentent le compteur.
        // ip4:, ip6:, all et exp ne génèrent pas de requête DNS (pas de coût).
        if (in_array($name, ['a', 'mx', 'include', 'exists', 'ptr'], true)) {
            $cost = 1;
            $lookups++;
        }

        // Le mécanisme "ptr" est explicitement déconseillé par la RFC 7208 §5.5
        // car il génère beaucoup de requêtes DNS et est lent.
        if ($name === 'ptr') {
            $warnings[] = 'Le mécanisme ptr est déconseillé dans SPF par la RFC 7208.';
        }

        // Détecte les mécanismes inconnus ou mal formés.
        if (!in_array($name, [
            'a', 'mx', 'ip4', 'ip6', 'include', 'exists', 'ptr', 'all', 'exp'
        ], true)) {
            $errors[] = 'Mécanisme SPF inconnu ou syntaxe invalide : ' . $name;
        }

        // Récursion sur les directives "include:" pour analyser l'arborescence complète.
        if ($name === 'include') {
            $incDomain = strtolower($value);
            $node      = [
                'parent'  => $currentDomain,
                'include' => $incDomain,
                'status'  => 'ok'
            ];

            if (isset($visited[$incDomain])) {
                // Ce domaine a déjà été inclus dans la chaîne → boucle d'inclusion.
                $errors[]       = "Boucle d'inclusion SPF détectée : $incDomain a déjà été exploré.";
                $node['status'] = 'loop';
            } elseif ($depth >= 10) {
                // RFC 7208 §4.6.4 : la profondeur d'imbrication ne doit pas dépasser 10.
                $errors[]       = "Profondeur maximale d'inclusion SPF dépassée (> 10 niveaux).";
                $node['status'] = 'max_depth';
            } else {
                $visited[$incDomain] = true;
                $incRecords          = getSpfRecords($incDomain);
                if (!empty($incRecords)) {
                    parseSpfRecursive(
                        $incDomain,
                        $incRecords[0],
                        $lookups,
                        $voidLookups,
                        $visited,
                        $tree,
                        $errors,
                        $warnings,
                        $depth + 1
                    );
                } else {
                    // L'include pointe vers un domaine sans enregistrement SPF valide.
                    $voidLookups++;
                    $warnings[]     = "L’include include:$incDomain n'a renvoyé aucun enregistrement SPF valide.";
                    $node['status'] = 'void';
                }
            }
            // Ajoute ce nœud à l'arbre des inclusions (pour visualisation dans l'interface).
            $tree[] = $node;
        }

        $mechanisms[] = [
            'name'      => $name,
            'value'     => $value,
            'qualifier' => $qualifier,
            'lookups'   => $cost
        ];
    }

    return [
        'mechanisms' => $mechanisms,
        'all'        => $all,
        'redirect'   => $redirect
    ];
}

/**
 * Vérifie la configuration SPF complète d'un domaine.
 *
 * Orchestration de l'analyse SPF :
 *   1. Récupère le ou les enregistrements SPF du domaine.
 *   2. Détecte les configurations invalides d'emblée (absent, multiples).
 *   3. Lance l'analyse récursive complète (parseSpfRecursive).
 *   4. Évalue les résultats : +all dangereux, ?all neutre, dépassement de lookups.
 *   5. Propose une correction DNS si +all est détecté.
 *
 * @param string $domain Domaine à analyser.
 * @return array         Résultat structuré avec status, message, record, details.
 */
function checkSpf(string $domain): array
{
    $records = getSpfRecords($domain);

    // Cas 1 : Aucun enregistrement SPF — les emails peuvent être usurpés librement.
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'SPF',
            'message'       => 'Aucun enregistrement SPF n’a été trouvé.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'TXT',
                'value' => 'v=spf1 mx ~all',
                'note'  => 'Enregistrement SPF initial autorisant vos serveurs MX.'
            ],
            'details'       => [
                'lookups' => 0,
                'limit'   => MAX_SPF_DNS_LOOKUPS
            ]
        ];
    }

    // Cas 2 : Plusieurs enregistrements SPF — interdit par la RFC 7208 §3.2.
    // Les serveurs récepteurs renverront systématiquement PermError, rendant SPF inutile.
    if (count($records) > 1) {
        return [
            'status'        => 'error',
            'title'         => 'SPF',
            'message'       => 'Plusieurs enregistrements SPF ont été détectés. La norme RFC 7208 impose STRICTEMENT un seul SPF par domaine (PermError sinon).',
            'record'        => implode("\n", $records),
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'TXT',
                'value' => 'v=spf1 [fusionnez vos mécanismes ici] ~all',
                'note'  => 'Regroupez tous vos ip4 et includes dans une seule ligne TXT unique.'
            ],
            'details'       => [
                'records' => $records
            ]
        ];
    }

    // Initialisation des compteurs et accumulateurs pour l'analyse récursive.
    $lookups     = 0;
    $voidLookups = 0;
    $visited     = [strtolower($domain) => true]; // Le domaine racine est marqué comme visité.
    $tree        = [];
    $errors      = [];
    $warnings    = [];

    // Lancement de l'analyse récursive sur l'enregistrement SPF unique.
    $parsed = parseSpfRecursive(
        $domain,
        $records[0],
        $lookups,
        $voidLookups,
        $visited,
        $tree,
        $errors,
        $warnings,
        0
    );

    $all      = $parsed['all'];
    $redirect = $parsed['redirect'];

    // Un SPF sans "all" ni "redirect" à la fin est ambiguë et déconseillé.
    if ($all === null && $redirect === null) {
        $warnings[] = 'Aucun mécanisme all ou redirect n’a été trouvé en fin d’enregistrement.';
    }

    // "+all" autorise TOUT le monde à envoyer des emails pour le domaine → danger critique.
    if ($all === '+') {
        $errors[] = 'Le SPF contient +all et autorise n’importe quel serveur dans le monde à envoyer des emails pour votre domaine !';
    } elseif ($all === '?') {
        // "?all" (neutre) n'offre aucune protection active contre l'usurpation d'identité.
        $warnings[] = 'Le SPF utilise ?all (Neutre) : cela n\'offre aucune protection active contre l\'usurpation.';
    }

    // RFC 7208 §4.6.4 : limite de 10 lookups DNS. Au-delà → PermError.
    if ($lookups > MAX_SPF_DNS_LOOKUPS) {
        $errors[] = "Dépassement de la limite RFC 7208 : $lookups recherches DNS requises (limite maximale : 10). Vos emails risquent d'être rejetés en PermError.";
    } elseif ($lookups >= 8) {
        // Alerte préventive : proche de la limite, un include supplémentaire peut tout casser.
        $warnings[] = "Attention : $lookups recherches DNS utilisées sur un maximum de 10. Votre SPF approche du quota maximum.";
    }

    // Trop de lookups vides peut indiquer des includes pointant vers des domaines inexistants.
    if ($voidLookups > 2) {
        $warnings[] = "Nombre de requêtes DNS vides élevé ($voidLookups).";
    }

    $status = 'ok';
    if ($errors) {
        $status = 'error';
    } elseif ($warnings) {
        $status = 'warning';
    }

    // Si +all est détecté, on propose directement le correctif : remplacer par ~all (SoftFail).
    $suggestedDns = null;
    if ($all === '+') {
        $suggestedDns = [
            'name'  => '@',
            'type'  => 'TXT',
            'value' => preg_replace('/\+all/', '~all', $records[0]),
            'note'  => 'Remplacement du +all par ~all pour bloquer les usurpateurs.'
        ];
    }

    return [
        'status'        => $status,
        'title'         => 'SPF',
        'message'       => $errors
            ? implode(' ', $errors)
            : ($warnings ? implode(' ', $warnings) : "Configuration SPF valide ($lookups/10 recherches DNS utilisées)."),
        'record'        => $records[0],
        'suggested_dns' => $suggestedDns,
        'details'       => [
            'lookups'       => $lookups,
            'limit'         => MAX_SPF_DNS_LOOKUPS,
            'void_lookups'  => $voidLookups,
            'mechanisms'    => $parsed['mechanisms'],
            'includes_tree' => $tree,
            'all'           => $all,
            'redirect'      => $redirect,
            'errors'        => $errors,
            'warnings'      => $warnings
        ]
    ];
}


/**
 * Analyse les tags d'un enregistrement DKIM brut et estime la taille de la clé RSA.
 *
 * Un enregistrement DKIM est une liste de paires clé=valeur séparées par des points-virgules.
 * Tags importants :
 *   - v= : version (doit être DKIM1)
 *   - k= : type de clé (rsa par défaut, ed25519 pour les clés modernes)
 *   - p= : clé publique encodée en Base64 (vide = clé révoquée)
 *
 * Estimation de la taille de clé RSA par décodage Base64 de p= :
 *   La taille en octets de la clé décodée permet d'estimer les bits :
 *   - ≤ 170 octets → ~1024 bits (déprécié, recommandé de migrer vers 2048)
 *   - ≤ 320 octets → ~2048 bits (standard actuel recommandé)
 *   - > 320 octets → ~4096 bits (haute sécurité)
 *   Note : c'est une estimation basée sur la taille, pas un décodage ASN.1 complet.
 *
 * @param string $record Enregistrement DKIM brut (ex: "v=DKIM1; k=rsa; p=MIGfMA0…").
 * @return array         Tags analysés, type et taille de clé, erreurs et avertissements.
 */
function parseDkim(string $record): array
{
    $tags = [];

    // Découpe en paires clé=valeur séparées par des points-virgules.
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    $errors   = [];
    $warnings = [];
    $keyBits  = null;
    $keyType  = strtolower($tags['k'] ?? 'rsa');

    // Vérification de la version DKIM (tag v=).
    if (
        isset($tags['v']) &&
        strtoupper($tags['v']) !== 'DKIM1'
    ) {
        $errors[] = 'Version DKIM incorrecte (attendu: DKIM1).';
    }

    // Vérification de la présence et de la validité de la clé publique (tag p=).
    if (!isset($tags['p'])) {
        $errors[] = 'Clé publique p= absente.';
    } elseif ($tags['p'] === '') {
        // Un p= vide signifie que la clé a été révoquée intentionnellement.
        $warnings[] = 'La clé DKIM est révoquée (p= vide).';
    } else {
        // Estimation de la taille de la clé RSA par décodage Base64 et mesure en octets.
        $decoded = @base64_decode($tags['p'], true);
        if ($decoded !== false) {
            $byteLen = strlen($decoded);
            if ($byteLen <= 170) {
                // 1024 bits : dépréciée par les standards modernes (NIST, RFC 8301).
                $keyBits    = 1024;
                $warnings[] = 'Clé RSA 1024 bits détectée : dépréciée par les standards modernes. Une clé de 2048 bits est recommandée.';
            } elseif ($byteLen <= 320) {
                // 2048 bits : taille recommandée, bonne sécurité actuelle.
                $keyBits = 2048;
            } else {
                // 4096 bits : haute sécurité, moins courant.
                $keyBits = 4096;
            }
        }
    }

    return [
        'tags'     => $tags,
        'key_type' => $keyType,
        'key_bits' => $keyBits,
        'errors'   => $errors,
        'warnings' => $warnings
    ];
}

/**
 * Vérifie un sélecteur DKIM spécifique pour un domaine.
 *
 * L'enregistrement DKIM se trouve à l'hôte DNS : {sélecteur}._domainkey.{domaine}
 * Si aucun enregistrement TXT n'est trouvé à cet hôte, retourne null.
 * Si un enregistrement existe mais ne ressemble pas à un DKIM valide (ni v=DKIM1 ni p=),
 * il est ignoré (pourrait être un autre enregistrement TXT au même hôte).
 *
 * @param string $domain   Domaine à vérifier (ex: "exemple.fr").
 * @param string $selector Sélecteur DKIM à tester (ex: "google", "selector1").
 * @return array|null      Résultat d'analyse du sélecteur, ou null si non trouvé.
 */
function checkDkimSelector(
    string $domain,
    string $selector
): ?array {

    $host = $selector . '._domainkey.' . $domain;

    $records = txtRecords($host);

    if (!$records) {
        return null; // Aucun enregistrement TXT à cet hôte.
    }

    // Concatène tous les morceaux TXT en un seul enregistrement.
    $record = implode('', $records);

    // Vérifie que l'enregistrement ressemble bien à un DKIM (contient v=DKIM1 ou p=).
    if (
        stripos($record, 'v=DKIM1') === false &&
        stripos($record, 'p=') === false
    ) {
        return null;
    }

    $parsed = parseDkim($record);

    $status = 'ok';
    if ($parsed['errors']) {
        $status = 'error';
    } elseif ($parsed['warnings']) {
        $status = 'warning';
    }

    return [
        'selector' => $selector,
        'host'     => $host,
        'record'   => $record,
        'status'   => $status,
        'tags'     => $parsed['tags'],
        'key_type' => $parsed['key_type'],
        'key_bits' => $parsed['key_bits'],
        'errors'   => $parsed['errors'],
        'warnings' => $parsed['warnings']
    ];
}

/**
 * Vérifie la configuration DKIM d'un domaine.
 *
 * Deux modes de fonctionnement selon que l'utilisateur a fourni un sélecteur ou non :
 *
 *   Mode sélecteur fourni :
 *     Vérifie uniquement ce sélecteur précis. Si absent → erreur avec suggestion DNS.
 *
 *   Mode découverte automatique (aucun sélecteur fourni) :
 *     Teste les 18 sélecteurs de DEFAULT_DKIM_SELECTORS un par un.
 *     Si au moins un est trouvé, retourne tous les sélecteurs valides.
 *     Si aucun n'est trouvé, retourne un avertissement (le sélecteur est probablement personnalisé).
 *
 * Note : il est techniquement impossible de découvrir un sélecteur arbitraire
 * via DNS public — le DNS ne permet pas d'interroger "tous les sous-domaines de _domainkey.*".
 *
 * @param string $domain   Domaine à vérifier.
 * @param string $selector Sélecteur DKIM fourni par l'utilisateur (ou chaîne vide).
 * @return array           Résultat structuré avec status, message, record, details.
 */
function checkDkim(
    string $domain,
    string $selector
): array {

    // Mode 1 : sélecteur fourni explicitement par l'utilisateur.
    if ($selector !== '') {
        $result = checkDkimSelector($domain, $selector);

        if (!$result) {
            return [
                'status'        => 'error',
                'title'         => 'DKIM',
                'message'       => 'Aucune clé DKIM n’a été trouvée pour le sélecteur « ' . $selector . ' ».',
                'record'        => '',
                'suggested_dns' => [
                    'name'  => $selector . '._domainkey.' . $domain,
                    'type'  => 'TXT',
                    'value' => 'v=DKIM1; k=rsa; p=VOTRE_CLE_PUBLIQUE_ICI',
                    'note'  => 'Activez DKIM chez votre fournisseur email et publiez la clé publique fournie.'
                ],
                'details'       => [
                    'selector' => $selector
                ]
            ];
        }

        return [
            'status'        => $result['status'],
            'title'         => 'DKIM',
            'message'       => 'Clé DKIM trouvée avec le sélecteur « ' . $selector . ' »' . ($result['key_bits'] ? " ({$result['key_bits']} bits)." : '.'),
            'record'        => $result['record'],
            'suggested_dns' => null,
            'details'       => $result
        ];
    }

    // Mode 2 : aucun sélecteur fourni → découverte automatique parmi 18 sélecteurs courants.
    $selectors = DEFAULT_DKIM_SELECTORS;
    $found     = [];

    foreach ($selectors as $candidate) {
        $result = checkDkimSelector($domain, $candidate);
        if ($result) {
            $found[] = $result;
        }
    }

    // Aucun sélecteur connu trouvé : le domaine utilise probablement un sélecteur personnalisé.
    if (!$found) {
        return [
            'status'        => 'warning',
            'title'         => 'DKIM',
            'message'       => 'Aucun sélecteur DKIM courant n’a été trouvé parmi les 18 sélecteurs testés. Votre messagerie utilise probablement un sélecteur personnalisé.',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'tested' => $selectors
            ]
        ];
    }

    // Détermine le statut global : si l'un des sélecteurs est en erreur, le statut global est erreur.
    $status = 'ok';
    foreach ($found as $item) {
        if ($item['status'] === 'error') {
            $status = 'error';
            break;
        }
        if ($item['status'] === 'warning') {
            $status = 'warning';
        }
    }

    return [
        'status'        => $status,
        'title'         => 'DKIM',
        'message'       => count($found) . ' sélecteur(s) DKIM trouvé(s) (' . implode(', ', array_column($found, 'selector')) . ').',
        'record'        => implode("\n---\n", array_column($found, 'record')),
        'suggested_dns' => null,
        'details'       => [
            'selectors' => $found
        ]
    ];
}


/**
 * Analyse les tags d'un enregistrement DMARC brut selon la RFC 7489.
 *
 * Tags DMARC et leur rôle :
 *   - v=DMARC1 : version obligatoire, doit être exactement "DMARC1"
 *   - p=        : politique principale (none, quarantine, reject)
 *                   none      → surveillance seule, aucun blocage
 *                   quarantine → emails non authentifiés mis en spam
 *                   reject    → emails non authentifiés bloqués et supprimés
 *   - sp=       : politique pour les sous-domaines (même valeurs que p=)
 *   - pct=      : pourcentage d'emails auxquels la politique s'applique (1-100)
 *   - adkim=    : alignement DKIM (r=relaxed, s=strict)
 *   - aspf=     : alignement SPF  (r=relaxed, s=strict)
 *   - rua=      : adresse(s) e-mail pour les rapports agrégés quotidiens
 *   - ruf=      : adresse(s) e-mail pour les rapports forensiques (échecs individuels)
 *
 * @param string $record Enregistrement DMARC brut.
 * @return array         Tags, erreurs bloquantes et avertissements.
 */
function parseDmarc(string $record): array
{
    $tags     = [];
    $errors   = [];
    $warnings = [];

    // Découpe en paires clé=valeur séparées par des points-virgules.
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    // Vérification de la version (v=DMARC1 est obligatoire et doit être exact).
    if (
        !isset($tags['v']) ||
        strtoupper($tags['v']) !== 'DMARC1'
    ) {
        $errors[] = 'v=DMARC1 est absent ou incorrect.';
    }

    // Vérification de la politique principale p= (obligatoire).
    if (!isset($tags['p'])) {
        $errors[] = 'La politique p= est absente.';
    } elseif (!in_array(
        strtolower($tags['p']),
        ['none', 'quarantine', 'reject'],
        true
    )) {
        $errors[] = 'La politique p= est invalide.';
    }

    // Vérification de la politique sous-domaine sp= (optionnelle mais si présente, doit être valide).
    if (isset($tags['sp']) &&
        !in_array(
            strtolower($tags['sp']),
            ['none', 'quarantine', 'reject'],
            true
        )
    ) {
        $errors[] = 'La politique sp= est invalide.';
    }

    // Vérification du pourcentage pct= (doit être entre 0 et 100).
    if (isset($tags['pct'])) {
        $pct = (int)$tags['pct'];
        if ($pct < 0 || $pct > 100) {
            $errors[] = 'pct= doit être compris entre 0 et 100.';
        } elseif ($pct < 100) {
            // Un pct< 100 signifie que la politique ne s'applique qu'à une fraction des emails.
            $warnings[] = "La politique ne s'applique qu'à $pct % des emails.";
        }
    }

    // Vérification de l'alignement DKIM adkim= (r=relaxed ou s=strict).
    if (
        isset($tags['adkim']) &&
        !in_array(strtolower($tags['adkim']), ['r', 's'], true)
    ) {
        $errors[] = 'adkim= doit être r ou s.';
    }

    // Vérification de l'alignement SPF aspf= (r=relaxed ou s=strict).
    if (
        isset($tags['aspf']) &&
        !in_array(strtolower($tags['aspf']), ['r', 's'], true)
    ) {
        $errors[] = 'aspf= doit être r ou s.';
    }

    // Avertissement si la politique est p=none (surveillance seule, aucune protection réelle).
    if (
        isset($tags['p']) &&
        strtolower($tags['p']) === 'none'
    ) {
        $warnings[] = 'La politique DMARC est actuellement en p=none (surveillance seule). Les emails non authentifiés ne sont pas bloqués.';
    }

    // Avertissement si aucune adresse de rapport agrégé n'est configurée.
    // Sans rua=, on ne peut pas savoir si des usurpateurs abusent du domaine.
    if (!isset($tags['rua'])) {
        $warnings[] = 'Aucune adresse de rapport agrégé rua= n’est configurée.';
    }

    return [
        'tags'     => $tags,
        'errors'   => $errors,
        'warnings' => $warnings
    ];
}


/**
 * Vérifie que les destinataires externes des rapports DMARC ont autorisé leur réception (RFC 7489).
 *
 * PROBLÈME RÉSOLU : Quand un enregistrement DMARC envoie des rapports vers un domaine tiers
 * (ex: un prestataire DMARC comme Postmark, Mailhardener, dmarcian), la RFC 7489 §7.1 exige
 * que ce domaine tiers publie un enregistrement DNS spécifique pour autoriser la réception.
 * Sans cet enregistrement, les serveurs récepteurs des emails ignorent silencieusement les
 * adresses de rapport → les rapports ne sont jamais envoyés malgré une configuration correcte.
 *
 * Format de l'enregistrement DNS d'autorisation requis :
 *   {domaine-audité}._report._dmarc.{domaine-destinataire}
 *   Valeur TXT attendue : "v=DMARC1" (suivi d'autres tags optionnels)
 *
 * Exemple : si exemple.fr envoie ses rapports à rapports@prestataire.com,
 * la vérification porte sur : exemple.fr._report._dmarc.prestataire.com
 *
 * Les adresses appartenant au même domaine de base que le domaine audité sont ignorées
 * (un domaine s'autorise lui-même implicitement).
 *
 * @param string $domain Domaine audité (ex: "exemple.fr").
 * @param string $rua    Valeur du tag rua= (peut contenir plusieurs adresses séparées par des virgules).
 * @param string $ruf    Valeur du tag ruf= (idem).
 * @return array         Tableau des vérifications externes, une entrée par domaine tiers unique.
 */
function checkExternalDmarcReports(string $domain, string $rua, string $ruf): array
{
    $externalChecks = [];

    // Fusion des listes rua= et ruf= en un seul tableau d'adresses à vérifier.
    $rawList = array_filter(array_merge(explode(',', $rua), explode(',', $ruf)));

    // Extraction du domaine de base (les 2 dernières parties) pour la comparaison.
    // Ex: "mail.exemple.fr" → "exemple.fr" pour ignorer les rapports vers son propre domaine.
    $domainParts = explode('.', strtolower($domain));
    $baseDomain  = count($domainParts) > 2 ? implode('.', array_slice($domainParts, -2)) : strtolower($domain);

    // Évite de vérifier deux fois le même domaine de destination.
    $checkedDomains = [];

    foreach ($rawList as $entry) {
        $entry = trim($entry);

        // Extraction du domaine de l'adresse mailto: (ex: "mailto:rapports@prestataire.com" → "prestataire.com").
        if (!preg_match('/mailto:\s*([^\s@]+)@([^\s!?,;]+)/i', $entry, $matches)) {
            continue; // Entrée malformée ou non-mailto → ignorée.
        }

        $destDomain     = strtolower(trim($matches[2]));
        $destParts      = explode('.', $destDomain);
        $baseDestDomain = count($destParts) > 2 ? implode('.', array_slice($destParts, -2)) : $destDomain;

        // On ignore les adresses appartenant au même domaine de base (auto-autorisation implicite).
        if ($baseDestDomain === $baseDomain) {
            continue;
        }

        // Ne vérifie qu'une seule fois par domaine de destination.
        if (isset($checkedDomains[$destDomain])) {
            continue;
        }
        $checkedDomains[$destDomain] = true;

        // Construction de l'hôte DNS à vérifier selon la RFC 7489 §7.1.
        $verifyHost   = $domain . '._report._dmarc.' . $destDomain;
        $txts         = txtRecords($verifyHost);
        $isAuthorized = false;

        // L'enregistrement d'autorisation doit contenir "v=DMARC1" en début de valeur.
        foreach ($txts as $txt) {
            if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
                $isAuthorized = true;
                break;
            }
        }

        $externalChecks[] = [
            'destination_domain' => $destDomain,
            'verify_host'        => $verifyHost,
            'is_authorized'      => $isAuthorized
        ];
    }

    return $externalChecks;
}

/**
 * Vérifie la configuration DMARC complète d'un domaine.
 *
 * Étapes d'analyse :
 *   1. Recherche l'enregistrement DMARC sous _dmarc.{domaine}.
 *   2. Si absent sur un sous-domaine, cherche sur le domaine parent (héritage RFC 7489).
 *   3. Détecte les erreurs critiques (absent, multiples, p= invalide…).
 *   4. Analyse les tags avec parseDmarc().
 *   5. Vérifie les autorisations de rapports externes avec checkExternalDmarcReports().
 *   6. Propose une migration DNS si la politique est encore p=none.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat structuré avec status, message, record, details incluant external_reports.
 */
function checkDmarc(string $domain): array
{
    $host        = '_dmarc.' . $domain;
    $records     = [];
    $isInherited = false;

    // Recherche de l'enregistrement DMARC du domaine.
    foreach (txtRecords($host) as $txt) {
        if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
            $records[] = trim($txt);
        }
    }

    // Si le domaine est un sous-domaine (ex: blog.exemple.fr) et n'a pas de DMARC propre,
    // la RFC 7489 §6.6.3 autorise l'héritage depuis le domaine parent (exemple.fr).
    if (!$records) {
        $parts = explode('.', $domain);
        if (count($parts) > 2) {
            $parent     = implode('.', array_slice($parts, 1));
            $parentHost = '_dmarc.' . $parent;
            foreach (txtRecords($parentHost) as $txt) {
                if (preg_match('/^v=DMARC1(?:\s|;|$)/i', trim($txt))) {
                    $records[]   = trim($txt);
                    $isInherited = true;
                    $host        = $parentHost; // Mise à jour de l'hôte pour l'affichage.
                }
            }
        }
    }

    // Cas 1 : Aucun enregistrement DMARC (ni sur le domaine, ni sur le parent).
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'DMARC',
            'message'       => 'Aucun enregistrement DMARC n’a été trouvé.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '_dmarc.' . $domain,
                'type'  => 'TXT',
                'value' => 'v=DMARC1; p=none; rua=mailto:dmarc-reports@' . $domain . '; pct=100; sp=none',
                'note'  => 'Enregistrement DMARC recommandé pour démarrer en mode surveillance.'
            ],
            'details'       => []
        ];
    }

    // Cas 2 : Plusieurs enregistrements DMARC → erreur de configuration.
    if (count($records) > 1) {
        return [
            'status'        => 'error',
            'title'         => 'DMARC',
            'message'       => 'Plusieurs enregistrements DMARC ont été détectés sous ' . $host . '.',
            'record'        => implode("\n", $records),
            'suggested_dns' => null,
            'details'       => []
        ];
    }

    // Analyse complète des tags DMARC.
    $parsed = parseDmarc($records[0]);
    $status = 'ok';

    // Vérification des autorisations de rapports vers des domaines externes (RFC 7489 §7.1).
    // Si un rapport est configuré vers prestataire.com mais que l'enregistrement DNS
    // d'autorisation est absent, les serveurs récepteurs n'enverront pas les rapports.
    $externalReports = checkExternalDmarcReports(
        $domain,
        $parsed['tags']['rua'] ?? '',
        $parsed['tags']['ruf'] ?? ''
    );
    foreach ($externalReports as $ext) {
        if (!$ext['is_authorized']) {
            $parsed['warnings'][] = "L’adresse de rapport vers @" . $ext['destination_domain'] . " nécessite un enregistrement DNS d'autorisation RFC 7489 à l'hôte '" . $ext['verify_host'] . "' (non trouvé). Les serveurs récepteurs peuvent refuser d'y envoyer vos rapports.";
        }
    }

    if ($parsed['errors']) {
        $status = 'error';
    } elseif ($parsed['warnings']) {
        $status = 'warning';
    }

    // Si la politique est encore p=none, on propose de passer à p=quarantine.
    // p=none = surveillance seule, aucun email n'est bloqué ou mis en spam.
    $suggestedDns = null;
    $currentP     = strtolower($parsed['tags']['p'] ?? '');
    if ($currentP === 'none') {
        $suggestedDns = [
            'name'  => '_dmarc.' . $domain,
            'type'  => 'TXT',
            'value' => preg_replace('/p=none/', 'p=quarantine', $records[0]),
            'note'  => 'Passage recommandé vers p=quarantine pour protéger activement votre domaine.'
        ];
    }

    return [
        'status'        => $status,
        'title'         => 'DMARC',
        'message'       => $parsed['errors']
            ? implode(' ', $parsed['errors'])
            : ($parsed['warnings'] ? implode(' ', $parsed['warnings']) : "Configuration DMARC conforme et active (p=$currentP)."),
        'record'        => $records[0],
        'suggested_dns' => $suggestedDns,
        'details'       => [
            'inherited'        => $isInherited,
            'host'             => $host,
            'tags'             => $parsed['tags'],
            'errors'           => $parsed['errors'],
            'warnings'         => $parsed['warnings'],
            'external_reports' => $externalReports
        ]
    ];
}


/**
 * Vérifie la configuration MX, le Reverse DNS (PTR) et le FCrDNS d'un domaine.
 *
 * Étapes d'analyse pour chaque serveur MX :
 *   1. Résolution des IPs (IPv4 + IPv6) du nom d'hôte MX.
 *   2. Pour chaque IP, recherche du PTR (Reverse DNS) via gethostbyaddr().
 *   3. Pour chaque PTR trouvé, vérification FCrDNS : le nom PTR résout-il vers la même IP ?
 *      (Forward-Confirmed Reverse DNS = double vérification nom ↔ IP)
 *
 * Pourquoi le FCrDNS est important :
 *   Certains filtres anti-spam vérifient la cohérence PTR ↔ A.
 *   Un serveur qui ne valide pas le FCrDNS peut voir ses emails rejetés ou mis en spam.
 *
 * Après l'analyse MX, appelle detectMailProvider() pour identifier le fournisseur.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, liste des serveurs, PTR, FCrDNS et fournisseur détecté.
 */
function checkMx(string $domain): array
{
    $records = mxRecords($domain);

    // Aucun serveur MX : le domaine ne peut pas recevoir d'emails.
    if (!$records) {
        return [
            'status'        => 'error',
            'title'         => 'MX et Reverse DNS',
            'message'       => 'Aucun serveur MX n’a été trouvé. Le domaine ne peut pas recevoir d’emails.',
            'record'        => '',
            'suggested_dns' => [
                'name'  => '@',
                'type'  => 'MX',
                'value' => '10 mail.' . $domain,
                'note'  => 'Configurez les serveurs MX fournis par votre messagerie.'
            ],
            'details'       => []
        ];
    }

    $servers        = [];
    $reverseWarning = false; // Vrai si au moins un PTR est absent.
    $fcrdnsWarning  = false; // Vrai si au moins un PTR ne résout pas vers la bonne IP.

    foreach ($records as $record) {
        $host      = rtrim((string)($record['target'] ?? ''), '.');
        $ips       = hostIPs($host);
        $addresses = [];

        foreach ($ips as $ip) {
            $ptr    = ptrRecord($ip);
            $hasPtr = ($ptr !== '');
            $fcrdns = false;

            if (!$hasPtr) {
                // IP sans PTR → problème potentiel de réputation e-mail.
                $reverseWarning = true;
            } else {
                // Test FCrDNS : le nom PTR résout-il bien vers cette même IP ?
                // Si non, la cohérence DNS est rompue (possible mauvaise configuration).
                $forwardIps = hostIPs($ptr);
                $fcrdns     = in_array($ip, $forwardIps, true);
                if (!$fcrdns) {
                    $fcrdnsWarning = true;
                }
            }

            $addresses[] = [
                'ip'      => $ip,
                'ptr'     => $ptr,
                'has_ptr' => $hasPtr,
                'fcrdns'  => $fcrdns
            ];
        }

        $servers[] = [
            'priority'  => (int)($record['pri'] ?? 0),
            'host'      => $host,
            'addresses' => $addresses
        ];
    }

    // Identification du fournisseur de messagerie basée sur les noms d'hôtes MX (et PTR en secours).
    $provider       = detectMailProvider($servers);
    $providerNotice = $provider ? ' (Messagerie : ' . $provider['name'] . ')' : '';

    // Détection d'un CNAME sur la racine (@) - RFC 1034 §3.6.2
    $rootCnames = dnsRecords($domain, DNS_CNAME);
    $cnameWarning = false;
    if (!empty($rootCnames)) {
        $cnameTarget = $rootCnames[0]['target'] ?? '';
        $cnameWarning = true;
    }

    $status  = 'ok';
    $message = count($servers) . ' serveur(s) MX configuré(s) avec Reverse DNS (PTR) opérationnel.' . $providerNotice;

    if ($cnameWarning) {
        $status  = 'error';
        $message = 'Anomalie critique RFC 1034 : un enregistrement CNAME a été détecté sur la racine (@). La norme interdit formellement les CNAME sur la racine car ils rendent inopérants vos MX et SPF !' . $providerNotice;
    } elseif ($reverseWarning) {
        $status  = 'warning';
        $message = 'Les MX sont présents, mais un ou plusieurs Reverse DNS (PTR) sont absents.' . $providerNotice;
    } elseif ($fcrdnsWarning) {
        $status  = 'warning';
        $message = 'Les PTR existent, mais certains ne valident pas le contrôle de réconciliation directe-inverse (FCrDNS).' . $providerNotice;
    }

    // Construction des lignes MX pour l'affichage de l'enregistrement brut.
    $mxLines = [];
    foreach ($servers as $s) {
        $mxLines[] = $s['priority'] . ' ' . $s['host'];
    }

    return [
        'status'        => $status,
        'title'         => 'MX et Reverse DNS',
        'message'       => $message,
        'record'        => implode("\n", $mxLines),
        'suggested_dns' => null,
        'provider'      => $provider,
        'details'       => [
            'servers'       => $servers,
            'provider'      => $provider,
            'cname_on_apex' => $cnameWarning
        ]
    ];
}


/**
 * Identifie le fournisseur de messagerie utilisé par un domaine.
 *
 * Algorithme en deux passes :
 *
 *   Passe 1 — Correspondance sur les noms d'hôtes MX :
 *     Vérifie si le nom d'hôte MX correspond exactement à un domaine connu,
 *     ou s'il se termine par ".domaine-connu" (sous-domaine).
 *     Exemple : "mx1.mail.protection.outlook.com" → Microsoft 365
 *
 *   Passe 2 — Correspondance sur le PTR (Reverse DNS) en secours :
 *     Si le MX utilise un nom d'hôte personnalisé (ex: "mail.mondomaine.com"),
 *     la passe 1 échoue. On vérifie alors le PTR de l'IP du serveur MX.
 *     Exemple : "mail.thierrylaval.dev" → IP → PTR "109-234-161-215.reverse.odns.fr" → o2switch
 *
 * 17 fournisseurs reconnus : Google Workspace, Microsoft 365, OVHcloud, Infomaniak,
 * Proton Mail, Fastmail, Zoho, Brevo, Mailjet, Mailgun, SendGrid, Apple iCloud,
 * Yahoo, Gandi, o2switch, Hostinger/Titan, IONOS.
 *
 * @param array $servers Tableau des serveurs MX avec leurs adresses IP et PTR (issu de checkMx).
 * @return array|null    Tableau ['slug' => ..., 'name' => ...] ou null si non identifié.
 */
function detectMailProvider(array $servers): ?array
{
    // Table de correspondance : slug → nom affiché + liste de domaines reconnus.
    $patterns = [
        'google'     => [
            'name'    => 'Google Workspace (Gmail Pro)',
            'domains' => ['google.com', 'googlemail.com', 'aspmx.l.google.com', 'l.google.com']
        ],
        'microsoft'  => [
            'name'    => 'Microsoft 365 / Exchange Online',
            'domains' => ['outlook.com', 'mail.protection.outlook.com', 'office365.com']
        ],
        'ovh'        => [
            'name'    => 'OVHcloud Mail',
            'domains' => ['ovh.net', 'ovh.ca', 'mail.ovh.net']
        ],
        'infomaniak' => [
            'name'    => 'Infomaniak Network',
            'domains' => ['infomaniak.ch', 'infomaniak.com']
        ],
        'proton'     => [
            'name'    => 'Proton Mail',
            'domains' => ['protonmail.ch', 'proton.me']
        ],
        'fastmail'   => [
            'name'    => 'Fastmail',
            'domains' => ['messagingengine.com', 'fastmail.com']
        ],
        'zoho'       => [
            'name'    => 'Zoho Mail',
            'domains' => ['zoho.com', 'zoho.eu']
        ],
        'brevo'      => [
            'name'    => 'Brevo (ex-Sendinblue)',
            'domains' => ['brevo.com', 'mailin-sms.com', 'sendinblue.com']
        ],
        'mailjet'    => [
            'name'    => 'Mailjet',
            'domains' => ['mailjet.com']
        ],
        'mailgun'    => [
            'name'    => 'Mailgun',
            'domains' => ['mailgun.org']
        ],
        'sendgrid'   => [
            'name'    => 'SendGrid (Twilio)',
            'domains' => ['sendgrid.net']
        ],
        'icloud'     => [
            'name'    => 'Apple iCloud Mail',
            'domains' => ['icloud.com']
        ],
        'yahoo'      => [
            'name'    => 'Yahoo Mail',
            'domains' => ['yahoodns.net', 'yahoo.com']
        ],
        'gandi'      => [
            'name'    => 'Gandi Mail',
            'domains' => ['gandi.net']
        ],
        'o2switch'   => [
            'name'    => 'o2switch Mail',
            'domains' => ['o2switch.net', 'odns.fr']
        ],
        'hostinger'  => [
            'name'    => 'Hostinger / Titan Mail',
            'domains' => ['hostinger.com', 'titan.email']
        ],
        'ionos'      => [
            'name'    => 'IONOS (1&1)',
            'domains' => ['kundenserver.de', 'ionos.com', '1and1.com', '1and1.fr']
        ]
    ];

    // Passe 1 : correspondance directe sur le nom d'hôte MX.
    foreach ($servers as $s) {
        $host = strtolower($s['host'] ?? '');
        foreach ($patterns as $slug => $def) {
            foreach ($def['domains'] as $d) {
                // Correspondance exacte OU sous-domaine (ex: "mx1.ovh.net" correspond à "ovh.net").
                if ($host === $d || (strlen($host) > strlen($d) && substr($host, -strlen('.' . $d)) === '.' . $d)) {
                    return ['slug' => $slug, 'name' => $def['name']];
                }
            }
        }
    }

    // Passe 2 : correspondance sur le PTR de l'IP (pour les MX avec nom d'hôte personnalisé).
    // Ex: "mail.thierrylaval.dev" n'est pas dans la table, mais son PTR "*.odns.fr" l'est.
    foreach ($servers as $s) {
        foreach ($s['addresses'] ?? [] as $addr) {
            $ptr = strtolower($addr['ptr'] ?? '');
            if ($ptr === '') {
                continue;
            }
            foreach ($patterns as $slug => $def) {
                foreach ($def['domains'] as $d) {
                    if ($ptr === $d || (strlen($ptr) > strlen($d) && substr($ptr, -strlen('.' . $d)) === '.' . $d)) {
                        return ['slug' => $slug, 'name' => $def['name']];
                    }
                }
            }
        }
    }

    // Fournisseur non identifié parmi les 17 connus.
    return null;
}


/**
 * Effectue une requête HTTP GET avec cURL (ou file_get_contents en secours).
 *
 * Utilisée uniquement pour vérifier le fichier de politique MTA-STS via HTTPS.
 * Le certificat SSL est vérifié (CURLOPT_SSL_VERIFYPEER = true) pour garantir
 * qu'on se connecte bien au bon serveur et non à un imposteur.
 *
 * Gestion de la compatibilité PHP 8.5+ :
 *   curl_close() est dépréciée en PHP 8.5. On utilise unset($ch) à la place,
 *   et on n'appelle curl_close() que si la version PHP est < 8.0 pour éviter
 *   un avertissement de dépréciation dans les logs serveur.
 *
 * Fallback sans cURL :
 *   Si l'extension cURL n'est pas disponible (rare mais possible sur certains hébergements),
 *   file_get_contents() est utilisé à la place avec un contexte de flux SSL.
 *
 * @param string $url URL HTTPS à récupérer.
 * @return array      Tableau avec 'ok' (bool), 'code' (int HTTP), 'body' (string), 'error' (string).
 */
function curlGet(string $url): array
{
    // Fallback si cURL n'est pas disponible : utilise file_get_contents avec contexte SSL.
    if (!function_exists('curl_init')) {
        $ctx  = stream_context_create([
            'http' => [
                'timeout'         => HTTP_TIMEOUT,
                'follow_location' => 1,
                'max_redirects'   => 3,
                'user_agent'      => 'DNS-Mail-Checker/2.0',
                'ignore_errors'   => true
            ],
            'ssl'  => [
                'verify_peer'      => true,
                'verify_peer_name' => true
            ]
        ]);
        $body = @file_get_contents($url, false, $ctx);
        return [
            'ok'    => ($body !== false),
            'code'  => ($body !== false ? 200 : 0),
            'body'  => ($body !== false ? (string)$body : ''),
            'error' => ($body === false ? 'Échec de connexion HTTPS.' : '')
        ];
    }

    // Requête cURL standard avec vérification SSL et timeout court.
    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_CONNECTTIMEOUT => HTTP_TIMEOUT,
        CURLOPT_TIMEOUT        => HTTP_TIMEOUT,
        CURLOPT_USERAGENT      => 'DNS-Mail-Checker/2.0',
        CURLOPT_SSL_VERIFYPEER => true,  // Vérifie le certificat SSL de la cible.
        CURLOPT_SSL_VERIFYHOST => 2      // Vérifie que le nom d'hôte correspond au certificat.
    ]);

    $body  = curl_exec($ch);
    $error = curl_error($ch);
    $code  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // PHP < 8.0 : curl_close() était recommandé pour libérer les ressources.
    // PHP >= 8.0 : les ressources cURL sont des objets gérés automatiquement par le GC.
    // PHP >= 8.5 : curl_close() est explicitement dépréciée.
    if (PHP_VERSION_ID < 80000) {
        @curl_close($ch);
    }
    unset($ch); // Libère la référence à l'objet cURL (déclenche le GC si PHP >= 8.0).

    return [
        'ok'    => ($body !== false && $code >= 200 && $code < 300),
        'code'  => $code,
        'body'  => ($body !== false) ? (string)$body : '',
        'error' => $error ?: ($code >= 400 ? "Code HTTP $code" : '')
    ];
}

/**
 * Vérifie la configuration MTA-STS d'un domaine.
 *
 * MTA-STS (RFC 8461) est un mécanisme qui force les serveurs qui vous envoient des emails
 * à utiliser une connexion TLS chiffrée. Sans MTA-STS, si le chiffrement TLS échoue,
 * certains serveurs anciens basculent en clair (non chiffré).
 *
 * MTA-STS nécessite DEUX éléments :
 *   1. Un enregistrement DNS TXT à "_mta-sts.{domaine}" (ex: "v=STSv1; id=202409301349")
 *   2. Un fichier de politique accessible en HTTPS à :
 *      "https://mta-sts.{domaine}/.well-known/mta-sts.txt"
 *      Ce fichier contient les directives mode, max_age et mx.
 *
 * Directives du fichier de politique :
 *   - mode: enforce  → TLS obligatoire, les emails non chiffrés sont rejetés
 *   - mode: testing  → TLS recommandé mais pas obligatoire, mode de transition
 *   - mode: none     → désactive MTA-STS
 *   - max_age: N     → durée de validité de la politique en secondes (ex: 604800 = 1 semaine)
 *   - mx: ...        → liste des noms de serveurs MX autorisés
 *
 * Note importante : ce test effectue une vraie requête HTTPS sortante depuis le serveur PHP.
 * Sur certains hébergements mutualisés restrictifs, cURL sortant peut être bloqué.
 * Dans ce cas, le test retournera un avertissement même si MTA-STS est correctement configuré.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, message, record et détails de la politique.
 */
function checkMtaSts(string $domain): array
{
    $host    = '_mta-sts.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=STSv1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=STSv1') === 0) {
            $records[] = trim($txt);
        }
    }

    // Cas 1 : Aucun DNS MTA-STS → non configuré (normal pour la grande majorité des domaines).
    if (!$records) {
        return [
            'status'        => 'warning',
            'title'         => 'MTA-STS',
            'message'       => 'MTA-STS n’est pas configuré. Il s’agit d’une protection complémentaire facultative qui renforce le chiffrement entre serveurs.',
            'record'        => '',
            'suggested_dns' => null, // Pas de suggestion DNS : sans le serveur HTTPS, le DNS seul serait inutile.
            'details'       => []
        ];
    }

    // Cas 2 : DNS MTA-STS présent → vérification du fichier de politique HTTPS.
    $url  = 'https://mta-sts.' . $domain . '/.well-known/mta-sts.txt';
    $http = curlGet($url);

    // Le DNS existe mais la politique HTTPS est inaccessible → configuration incomplète.
    if (!$http['ok']) {
        return [
            'status'        => 'warning',
            'title'         => 'MTA-STS',
            'message'       => 'Le DNS MTA-STS existe mais la politique HTTPS n’a pas pu être récupérée (' . $url . ').',
            'record'        => $records[0],
            'suggested_dns' => null,
            'details'       => [
                'url'   => $url,
                'code'  => $http['code'],
                'error' => $http['error']
            ]
        ];
    }

    // Analyse ligne par ligne du fichier de politique mta-sts.txt.
    $mode   = '';
    $maxAge = '';
    $mx     = [];

    foreach (preg_split('/\R/', $http['body']) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, ':') === false) {
            continue;
        }
        [$key, $value] = explode(':', $line, 2);
        $key           = strtolower(trim($key));
        $value         = trim($value);

        if ($key === 'mode') {
            $mode = strtolower($value);
        } elseif ($key === 'max_age') {
            $maxAge = $value;
        } elseif ($key === 'mx') {
            $mx[] = $value;
        }
    }

    // Validation des directives obligatoires du fichier de politique.
    $errors = [];
    if ($mode === '') {
        $errors[] = 'Directive mode absente.';
    } elseif (!in_array($mode, ['enforce', 'testing', 'none'], true)) {
        $errors[] = "Mode '$mode' invalide (doit être enforce, testing ou none).";
    }

    if ($maxAge === '') {
        $errors[] = 'Directive max_age absente.';
    }

    if (!$mx) {
        $errors[] = 'Aucune directive mx trouvée.';
    }

    return [
        'status'        => $errors ? 'error' : 'ok',
        'title'         => 'MTA-STS',
        'message'       => $errors ? implode(' ', $errors) : "La politique MTA-STS est accessible et valide (mode: $mode, max_age: $maxAge s).",
        'record'        => $records[0],
        'suggested_dns' => null,
        'details'       => [
            'url'     => $url,
            'mode'    => $mode,
            'max_age' => $maxAge,
            'mx'      => $mx,
            'policy'  => trim($http['body']) // Corps complet du fichier de politique pour affichage.
        ]
    ];
}


/**
 * Vérifie la configuration TLS-RPT d'un domaine.
 *
 * TLS-RPT (RFC 8460) est un mécanisme de reporting qui permet de recevoir automatiquement
 * des rapports quotidiens sur les connexions TLS échouées lors des échanges e-mail.
 * Ces rapports sont envoyés par les grands serveurs de messagerie (Gmail, Outlook…)
 * et aident à détecter des problèmes de certificats ou de compatibilité TLS.
 *
 * L'enregistrement DNS se trouve à : "_smtp._tls.{domaine}"
 * Format : "v=TLSRPTv1; rua=mailto:tls-reports@exemple.fr"
 *
 * Le tag rua= désigne l'adresse (ou URL HTTPS) où les rapports sont envoyés.
 * Sans rua=, l'enregistrement TLS-RPT est présent mais inutile (aucun rapport ne sera envoyé).
 *
 * Pourquoi aucune suggestion DNS n'est proposée :
 *   Suggérer "rua=mailto:tls-reports@exemple.fr" serait dangereux si cette boîte mail
 *   n'existe pas réellement. Les rapports TLS génèrent du trafic e-mail entrant significatif.
 *   L'utilisateur doit d'abord créer la boîte mail, puis configurer l'enregistrement.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat avec status, message, record et tags analysés.
 */
function checkTlsRpt(string $domain): array
{
    $host    = '_smtp._tls.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=TLSRPTv1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=TLSRPTv1') === 0) {
            $records[] = trim($txt);
        }
    }

    // Aucun enregistrement TLS-RPT : non configuré (très courant, ce n'est pas une erreur critique).
    if (!$records) {
        return [
            'status'        => 'warning',
            'title'         => 'TLS-RPT',
            'message'       => 'TLS-RPT n’est pas configuré. Il s’agit d’un service optionnel permettant de recevoir des bilans sur les connexions sécurisées.',
            'record'        => '',
            'suggested_dns' => null, // Pas de suggestion : l'adresse e-mail doit exister avant de la publier.
            'details'       => []
        ];
    }

    // Analyse des tags de l'enregistrement TLS-RPT.
    $tags = [];
    foreach (explode(';', $records[0]) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    // Le tag rua= est obligatoire pour que les rapports soient effectivement envoyés.
    $status = isset($tags['rua']) ? 'ok' : 'warning';

    return [
        'status'        => $status,
        'title'         => 'TLS-RPT',
        'message'       => isset($tags['rua'])
            ? 'TLS-RPT est configuré avec destination des rapports.'
            : 'TLS-RPT existe mais le paramètre rua= est absent.',
        'record'        => $records[0],
        'suggested_dns' => null,
        'details'       => [
            'tags' => $tags
        ]
    ];
}


/**
 * Vérifie la configuration BIMI d'un domaine.
 *
 * BIMI (Brand Indicators for Message Identification) est un standard qui permet
 * aux entreprises d'afficher leur logo officiel à côté de leurs emails dans
 * la boîte de réception des destinataires (Gmail, Apple Mail, Yahoo Mail).
 *
 * L'enregistrement DNS se trouve à : "default._bimi.{domaine}"
 * Format : "v=BIMI1; l=https://exemple.fr/logo.svg; a=https://exemple.fr/cert.pem"
 *
 * Tags BIMI :
 *   - v=BIMI1 : version obligatoire
 *   - l=      : URL HTTPS du logo SVG (format SVG Tiny P.S. requis par Gmail/Yahoo)
 *   - a=      : URL HTTPS du certificat VMC (optionnel, requis pour affichage garanti sur Gmail)
 *
 * Conditions requises pour que BIMI fonctionne sur Gmail et Yahoo :
 *   - DMARC doit être en p=quarantine avec pct=100, OU en p=reject
 *   - Le logo doit être en format SVG Tiny P.S. (pas un SVG ordinaire)
 *   - Pour Gmail : un certificat VMC payant (~300$/an) chez Entrust ou DigiCert
 *
 * Statut "info" (pas "warning") :
 *   Si BIMI n'est pas configuré, ce n'est PAS une erreur ni un avertissement.
 *   C'est une fonctionnalité optionnelle purement marketing. Le statut "info"
 *   est utilisé pour l'afficher sans le comptabiliser dans le score de sécurité.
 *
 * @param string $domain      Domaine à vérifier.
 * @param array  $dmarcResult Résultat DMARC pré-calculé (pour vérifier la compatibilité DMARC).
 * @return array              Résultat avec status ('info', 'ok', 'warning', 'error'), record et details.
 */
function checkBimi(string $domain, array $dmarcResult): array
{
    $host    = 'default._bimi.' . $domain;
    $records = [];

    // Filtre les enregistrements TXT pour ne garder que ceux qui commencent par "v=BIMI1".
    foreach (txtRecords($host) as $txt) {
        if (stripos(trim($txt), 'v=BIMI1') === 0) {
            $records[] = trim($txt);
        }
    }

    // BIMI non configuré : statut "info" (informatif, pas une erreur, ne pénalise pas le score).
    if (!$records) {
        return [
            'status'        => 'info',
            'title'         => 'BIMI (Logo de marque)',
            'message'       => 'BIMI n’est pas configuré. C’est une option marketing permettant d’afficher le logo officiel de votre marque dans les boîtes de réception (Gmail, Apple Mail, Yahoo).',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'configured' => false
            ]
        ];
    }

    // BIMI trouvé : analyse complète des tags.
    $record = $records[0];
    $tags   = [];
    foreach (explode(';', $record) as $part) {
        $part = trim($part);
        if ($part === '' || strpos($part, '=') === false) {
            continue;
        }
        [$key, $value]              = explode('=', $part, 2);
        $tags[strtolower(trim($key))] = trim($value);
    }

    $errors   = [];
    $warnings = [];

    // Vérification de la version BIMI (v=BIMI1 obligatoire).
    if (!isset($tags['v']) || strtoupper($tags['v']) !== 'BIMI1') {
        $errors[] = 'La version v=BIMI1 est absente ou incorrecte.';
    }

    // Vérification de l'URL du logo SVG (tag l=).
    $logoUrl = $tags['l'] ?? '';
    if ($logoUrl === '') {
        $errors[] = 'Le tag l= (URL du logo SVG) est manquant.';
    } elseif (!filter_var($logoUrl, FILTER_VALIDATE_URL) || stripos($logoUrl, 'https://') !== 0) {
        // L'URL du logo doit être en HTTPS pour des raisons de sécurité.
        $errors[] = 'L’URL du logo (l=) doit être en HTTPS.';
    } elseif (!preg_match('/\.svg(\?.*)?$/i', $logoUrl)) {
        // Le format SVG Tiny P.S. est requis (un fichier PNG ou JPG ne fonctionnera pas).
        $warnings[] = 'Le fichier logo (l=) doit être un fichier vectoriel .svg (recommandé SVG Tiny P.S.).';
    }

    // Vérification du certificat VMC optionnel (tag a=).
    // Le VMC (Verified Mark Certificate) est requis par Gmail pour afficher le logo de façon certifiée.
    $certUrl = $tags['a'] ?? '';
    if ($certUrl !== '' && (!filter_var($certUrl, FILTER_VALIDATE_URL) || stripos($certUrl, 'https://') !== 0)) {
        $warnings[] = 'L’URL du certificat VMC (a=) doit être en HTTPS.';
    }

    // Vérification de la compatibilité DMARC pour BIMI.
    // Gmail et Yahoo n'activent BIMI que si DMARC est en p=reject OU p=quarantine avec pct=100.
    // Un DMARC en p=none ou pct<100 = BIMI visible dans le DNS mais ignoré par les messageries.
    $dmarcTags      = $dmarcResult['details']['tags'] ?? [];
    $dmarcPolicy    = strtolower($dmarcTags['p'] ?? '');
    $dmarcPct       = isset($dmarcTags['pct']) ? (int)$dmarcTags['pct'] : 100;
    $dmarcCompatible = false;

    if ($dmarcPolicy === 'reject' || ($dmarcPolicy === 'quarantine' && $dmarcPct === 100)) {
        $dmarcCompatible = true;
    } else {
        $warnings[] = 'BIMI est détecté mais sera ignoré par Gmail et Yahoo : DMARC doit être configuré en p=quarantine (avec pct=100) ou p=reject.';
    }

    $status  = $errors ? 'error' : ($warnings ? 'warning' : 'ok');
    $message = $errors
        ? implode(' ', $errors)
        : ($warnings ? implode(' ', $warnings) : 'Enregistrement BIMI valide et conforme aux exigences DMARC.');

    return [
        'status'        => $status,
        'title'         => 'BIMI (Logo de marque)',
        'message'       => $message,
        'record'        => $record,
        'suggested_dns' => null,
        'details'       => [
            'configured'       => true,
            'host'             => $host,
            'tags'             => $tags,
            'logo_url'         => $logoUrl,
            'cert_url'         => $certUrl,
            'dmarc_compatible' => $dmarcCompatible,
            'errors'           => $errors,
            'warnings'         => $warnings
        ]
    ];
}


/**
 * Vérifie les adresses IPv4 associées aux serveurs MX sur plusieurs listes RBL / DNSBL.
 * Ce contrôle porte sur les IP de réception résolues, pas sur les IP d'envoi réellement utilisées.
 *
 * Les Real-time Blackhole Lists (RBL) sont des bases de données réputées qui répertorient
 * les adresses IP identifiées comme émettrices de spam ou compromises.
 * Les grands services de messagerie (Gmail, Microsoft 365, Yahoo) consultent ces listes
 * en temps réel pour décider d'accepter, de rejeter ou de classer en spam les emails.
 *
 * Fonctionnement par requête DNS inverse :
 *   Pour l'adresse IP A.B.C.D, on interroge en DNS de type A :
 *   D.C.B.A.{rbl-host}
 *   Si la réponse DNS est vide (NXDOMAIN) : l'IP est saine (non listée).
 *   Si la réponse renvoie une IP 127.0.0.x : l'IP est inscrite sur la liste noire.
 *
 * Listes noires publiques interrogées :
 *   - Spamcop (bl.spamcop.net)
 *   - Barracuda (b.barracudacentral.org)
 *   - SURRIEL PSBL (psbl.surriel.com)
 *   - UCEPROTECT Niveau 1 (dnsbl-1.uceprotect.net)
 *
 * @param array $mxServers Tableau des serveurs MX retourné par checkMx.
 * @return array           Résultat structuré avec status ('ok', 'warning', 'error'), message et détails.
 */
function checkRbl(array $mxServers): array
{
    $rbls = [
        'Spamcop'      => 'bl.spamcop.net',
        'Barracuda'    => 'b.barracudacentral.org',
        'SURRIEL PSBL' => 'psbl.surriel.com',
        'UCEPROTECT 1' => 'dnsbl-1.uceprotect.net'
    ];

    $testedIps = [];
    $listedResults = [];

    // Récupérer toutes les adresses IPv4 distinctes des serveurs MX (max 4 pour la rapidité)
    foreach ($mxServers as $server) {
        foreach ($server['addresses'] ?? [] as $addr) {
            $ip = $addr['ip'] ?? '';
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $testedIps[$ip] = true;
            }
        }
    }

    $ipList = array_slice(array_keys($testedIps), 0, 4);

    if (empty($ipList)) {
        return [
            'status'        => 'info',
            'title'         => 'RBL des IP MX',
            'message'       => 'Aucune adresse IPv4 des serveurs MX n’a pu être testée sur les listes RBL. Ce contrôle ne renseigne pas sur les IP d’envoi.',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => [
                'checked_ips' => [],
                'listed'      => []
            ]
        ];
    }

    $detailedChecks = [];

    foreach ($ipList as $ip) {
        $parts = explode('.', $ip);
        $revIp = implode('.', array_reverse($parts));

        foreach ($rbls as $rblName => $rblHost) {
            $query = $revIp . '.' . $rblHost;
            $res = @dns_get_record($query, DNS_A);
            $isListed = false;
            $returnIp = '';

            if (!empty($res)) {
                $returnIp = $res[0]['ip'] ?? '';
                // 127.0.0.x = listé ; ignorer les codes d'erreur de résolveur comme 127.255.255.x
                if (strpos($returnIp, '127.0.0.') === 0) {
                    $isListed = true;
                    $listedResults[] = [
                        'ip'  => $ip,
                        'rbl' => $rblName
                    ];
                }
            }

            $detailedChecks[] = [
                'ip'        => $ip,
                'rbl'       => $rblName,
                'is_listed' => $isListed,
                'return_ip' => $returnIp
            ];
        }
    }

    if (count($listedResults) > 0) {
        $warnings = [];
        foreach ($listedResults as $l) {
            $warnings[] = "L’adresse IP {$l['ip']} est répertoriée sur {$l['rbl']}.";
        }
        return [
            'status'        => 'error',
            'title'         => 'RBL des IP MX',
            'message'       => 'Une ou plusieurs IP de réception associées aux MX figurent sur une liste RBL : ' . implode(' ', $warnings) . ' Ce résultat ne permet pas de conclure sur la réputation des IP d’envoi réellement utilisées.',
            'record'        => implode(', ', array_unique(array_column($listedResults, 'ip'))),
            'suggested_dns' => null,
            'details'       => [
                'checked_ips' => $ipList,
                'checks'      => $detailedChecks,
                'listed'      => $listedResults
            ]
        ];
    }

    return [
        'status'        => 'ok',
        'title'         => 'RBL des IP MX',
        'message'       => 'Aucune des IP MX testées ne figure sur les listes RBL consultées (' . implode(', ', array_keys($rbls)) . '). Ce résultat ne renseigne pas sur les IP d’envoi réellement utilisées.',
        'record'        => implode(', ', $ipList),
        'suggested_dns' => null,
        'details'       => [
            'checked_ips' => $ipList,
            'checks'      => $detailedChecks,
            'listed'      => []
        ]
    ];
}


/**
 * Vérifie l'activation de DNSSEC pour le domaine.
 *
 * DNSSEC (Domain Name System Security Extensions) ajoute une couche de signatures
 * cryptographiques à la zone DNS. Il empêche les attaques par empoisonnement de cache
 * (DNS cache poisoning) et garantit que les enregistrements MX, SPF et DKIM reçus
 * n'ont pas été falsifiés ou détournés par un pirate sur le réseau.
 *
 * Détection via l'API DNS-over-HTTPS (DoH) Google :
 *   Interroge les enregistrements DS (Delegation Signer, type RFC 43) publiés dans la zone parente.
 *   Si un enregistrement DS est présent et valide, DNSSEC est actif.
 *
 * @param string $domain Domaine à vérifier.
 * @return array         Résultat structuré ('ok' si actif, 'info' si non configuré).
 */
function checkDnssec(string $domain): array
{
    $url = 'https://dns.google/resolve?name=' . urlencode($domain) . '&type=DS';
    $http = curlGet($url);

    if (!$http['ok']) {
        return [
            'status'        => 'info',
            'title'         => 'DNSSEC (Signature DNS)',
            'message'       => 'Impossible de vérifier DNSSEC (accès réseau DoH non disponible).',
            'record'        => '',
            'suggested_dns' => null,
            'details'       => ['enabled' => false]
        ];
    }

    $data = @json_decode($http['body'], true);
    $answers = $data['Answer'] ?? [];
    $dsRecords = [];

    foreach ($answers as $ans) {
        if (($ans['type'] ?? 0) === 43 && !empty($ans['data'])) {
            $dsRecords[] = (string)$ans['data'];
        }
    }

    if (!empty($dsRecords)) {
        return [
            'status'        => 'ok',
            'title'         => 'DNSSEC (Signature DNS)',
            'message'       => 'DNSSEC est activé. Votre zone DNS est protégée par signature cryptographique contre l’usurpation et le détournement.',
            'record'        => implode("\n", $dsRecords),
            'suggested_dns' => null,
            'details'       => [
                'enabled'    => true,
                'ds_records' => $dsRecords
            ]
        ];
    }

    return [
        'status'        => 'info',
        'title'         => 'DNSSEC (Signature DNS)',
        'message'       => 'DNSSEC n’est pas activé. Il s’agit d’une sécurité avancée facultative qui s’active généralement chez votre bureau d’enregistrement (Registrar).',
        'record'        => '',
        'suggested_dns' => null,
        'details'       => [
            'enabled' => false
        ]
    ];
}


/**
 * Vérifie la configuration DANE / TLSA sur les serveurs de messagerie MX.
 *
 * DANE (RFC 7672) permet de lier directement le certificat SSL/TLS d'un serveur de messagerie
 * à un enregistrement DNS de type TLSA (sur le port 25 : _25._tcp.mx-host).
 * Il complète MTA-STS en assurant un chiffrement TLS garanti sans risque d'attaque par
 * substitution de certificat intermédiaire.
 *
 * @param array $mxServers Serveurs MX retournés par checkMx.
 * @return array           Résultat structuré ('ok' si présent, 'info' si absent).
 */
function checkDane(array $mxServers): array
{
    $foundDane = [];

    foreach (array_slice($mxServers, 0, 3) as $s) {
        $host = $s['host'] ?? '';
        if ($host === '') continue;

        $tlsaHost = '_25._tcp.' . $host;
        $url = 'https://dns.google/resolve?name=' . urlencode($tlsaHost) . '&type=TLSA';
        $http = curlGet($url);

        if ($http['ok']) {
            $data = @json_decode($http['body'], true);
            $answers = $data['Answer'] ?? [];
            foreach ($answers as $ans) {
                if (($ans['type'] ?? 0) === 52 && !empty($ans['data'])) {
                    $foundDane[] = [
                        'host'   => $host,
                        'record' => (string)$ans['data']
                    ];
                }
            }
        }
    }

    if (!empty($foundDane)) {
        $lines = [];
        foreach ($foundDane as $d) {
            $lines[] = $d['host'] . ' : ' . $d['record'];
        }
        return [
            'status'        => 'ok',
            'title'         => 'DANE / TLSA',
            'message'       => 'DANE / TLSA est configuré sur vos serveurs MX. Vos certificats de messagerie sont authentifiés par le DNS.',
            'record'        => implode("\n", $lines),
            'suggested_dns' => null,
            'details'       => [
                'enabled' => true,
                'records' => $foundDane
            ]
        ];
    }

    return [
        'status'        => 'info',
        'title'         => 'DANE / TLSA',
        'message'       => 'DANE / TLSA n’est pas configuré. C’est une protection avancée facultative qui renforce l’authenticité des certificats de messagerie.',
        'record'        => '',
        'suggested_dns' => null,
        'details'       => [
            'enabled' => false
        ]
    ];
}


/**
 * Calcule un indicateur de configuration et de sécurité e-mail sur 100 points.
 * Ce score ne mesure pas la délivrabilité et inclut 10 points liés aux RBL des IP MX testées.
 *
 * Barème équilibré sur 100 points :
 *   MX & Reverse DNS : ok=20, warning=10, error=0  (réception + PTR/FCrDNS)
 *   SPF              : ok=20, warning=10, error=0  (autorisation des expéditeurs)
 *   DKIM             : ok=20, warning=10, error=0  (signature cryptographique)
 *   DMARC            : reject=20, quarantine=16, none=10, warning=8, error=0 (politique anti-usurpation)
 *   Listes Noires RBL: ok=10, error=0              (résultat des IP MX testées, pas des IP d'envoi)
 *   DNSSEC           : ok=5                        (sécurité de la zone DNS)
 *   MTA-STS ou DANE  : ok=5                        (chiffrement garanti inter-serveurs)
 *
 * Total maximal : 20 + 20 + 20 + 20 + 10 + 5 + 5 = 100 points.
 *
 * @param array $results Tableau des résultats de tous les tests.
 * @return int           Score de 0 à 100.
 */
function calculateScore(array $results): int
{
    $score = 0;

    // MX (20 pts max) : présence et qualité des serveurs de réception.
    if ($results['mx']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['mx']['status'] === 'warning') {
        $score += 10;
    }

    // SPF (20 pts max) : protection contre l'usurpation d'identité des expéditeurs.
    if ($results['spf']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['spf']['status'] === 'warning') {
        $score += 10;
    }

    // DKIM (20 pts max) : signature cryptographique des emails sortants.
    if ($results['dkim']['status'] === 'ok') {
        $score += 20;
    } elseif ($results['dkim']['status'] === 'warning') {
        $score += 10;
    }

    // DMARC (20 pts max) : politique de traitement des emails non authentifiés.
    if ($results['dmarc']['status'] === 'ok') {
        $policy = $results['dmarc']['details']['tags']['p'] ?? '';
        if ($policy === 'reject') {
            $score += 20;
        } elseif ($policy === 'quarantine') {
            $score += 16;
        } else {
            $score += 10; // p=none
        }
    } elseif ($results['dmarc']['status'] === 'warning') {
        $score += 8;
    }

    // Listes RBL (10 pts max) : résultat des IP MX testées, sans mesure des IP d'envoi.
    if (isset($results['rbl']) && $results['rbl']['status'] === 'ok') {
        $score += 10;
    }

    // DNSSEC (5 pts max) : protection cryptographique de la zone DNS.
    if (isset($results['dnssec']) && $results['dnssec']['status'] === 'ok') {
        $score += 5;
    }

    // Chiffrement garanti (MTA-STS ou DANE) (5 pts max).
    $hasMtaSts = isset($results['mtasts']) && $results['mtasts']['status'] === 'ok';
    $hasDane   = isset($results['dane']) && $results['dane']['status'] === 'ok';
    if ($hasMtaSts || $hasDane) {
        $score += 5;
    }

    return $score;
}


/**
 * EXÉCUTION PRINCIPALE — Lance tous les tests et retourne le rapport JSON complet.
 */

// Calcul DMARC et MX en premier pour réutiliser leurs résultats dans les tests dépendants.
$dmarcResult = checkDmarc($domain);
$mxResult    = checkMx($domain);
$mxServers   = $mxResult['details']['servers'] ?? [];

// Exécution de tous les tests dans l'ordre d'affichage logique.
$results = [
    'mx'     => $mxResult,
    'spf'    => checkSpf($domain),
    'dkim'   => checkDkim($domain, $selector),
    'dmarc'  => $dmarcResult,
    'rbl'    => checkRbl($mxServers),
    'dnssec' => checkDnssec($domain),
    'bimi'   => checkBimi($domain, $dmarcResult),
    'dane'   => checkDane($mxServers),
    'mtasts' => checkMtaSts($domain),
    'tlsrpt' => checkTlsRpt($domain)
];

$errors       = 0;
$warnings     = 0;
$suggestedDns = [];

// Parcours des résultats pour compter les statuts et collecter les suggestions DNS.
foreach ($results as $k => $result) {
    if ($result['status'] === 'error') {
        $errors++;
    } elseif ($result['status'] === 'warning') {
        $warnings++;
        // Note : 'info' n'incrémente pas le compteur d'avertissements.
    }
    if (!empty($result['suggested_dns'])) {
        $suggestedDns[$k] = array_merge($result['suggested_dns'], [
            'category' => $result['title']
        ]);
    }
}

// Statut global : erreur si au moins un test en erreur, avertissement sinon, ok si tout est propre.
$globalStatus = $errors > 0 ? 'error' : ($warnings > 0 ? 'warning' : 'ok');
$score        = calculateScore($results);

// Envoi de la réponse JSON finale.
response([
    'success'       => true,
    'domain'        => $domain,
    'score'         => $score,
    'status'        => $globalStatus,
    'summary'       => [
        'errors'   => $errors,
        'warnings' => $warnings
    ],
    'results'       => $results,
    'suggested_dns' => $suggestedDns
]);
