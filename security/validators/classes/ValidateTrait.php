<?php
/**  ______ _                 _               _ ___
 *  |  ____| |               | |             | |__ \
 *  | |__  | |_   ___      __| |__   ___  ___| |  ) |
 *  |  __| | | | | \ \ /\ / /| '_ \ / _ \/ _ \ | / /
 *  | |    | | |_| |\ V  V / | | | |  __/  __/ |/ /_
 *  |_|    |_|\__, | \_/\_/  |_| |_|\___|\___|_|____|
 *             __/ |
 *            |___/
 *
 * Flywheel2: the inertia php framework
 *
 * @category	Flywheel2
 * @package		security
 * @author		wakaba <wakabadou@gmail.com>
 * @copyright	2011- Wakabadou honpo (http://www.wakabadou.net/) / Project ICKX (http://www.ickx.jp/)
 * @license		http://opensource.org/licenses/MIT The MIT License MIT
 * @varsion		2.0.0
 */

namespace ickx\fw2\security\validators\traits;

use ickx\fw2\vartype\arrays\Arrays;
use ickx\fw2\international\encoding\Encoding;
use ickx\fw2\vartype\strings\Strings;
use ickx\fw2\other\network\DomainUtility;
use ickx\fw2\constants\web\ColorCode;

/**
 * 検証特性です。
 *
 * 検証ルールの実体をもちます。
 *
 * @category	Flywheel2
 * @package		security
 * @author		wakaba <wakabadou@gmail.com>
 * @license		http://opensource.org/licenses/MIT The MIT License MIT
 * @varsion		2.0.0
 */
class ValidateTrait {
	/**
	 * 基本ルール構築
	 *
	 * @param	string	$rule_name	ルール名
	 * @param	array	$rule		ルール
	 */
	public static function DefaultRule () {
		return array(
			//状態
			static::RULE_REQUIRE			=> array(function ($value, $options, $meta = array()) {return $value !== null;}, '必須入力項目 {:title}が入力されていません。'),
			static::RULE_NOT_EMPTY			=> array(function ($value, $options, $meta = array()) {return (is_array($value)) ? !empty($value) : preg_match("/[^\s]+/um", $value) === 1;}, '{:title}を入力してください。'),
			static::RULE_NOT_STRING_EMPTY	=> array(function ($value, $options, $meta = array()) {return (is_array($value)) ? !empty($value) : trim($value, "\r\n") !== '';}, '{:title}を入力してください。'),

			//逆状態
			static::RULE_NOT_REQUIRE		=> array(function ($value, $options, $meta = array()) {return $value === null;}, '必須除外項目 {:title}が入力されました。'),

			//スカラー値
			'bool'			=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_BOOLEAN);}, '{:title}には1, true, on, yesのいずれかを入力してください。'),
			'int'			=> array(function ($value, $options, $meta = array()) {return is_int(filter_var($value, \FILTER_VALIDATE_INT)) && 0 === preg_match("/\A[^0-9\-\+eEx]\z/", $value);}, '{:title}には整数を入力してください。'),
			'positive_int'	=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_INT) > -1;}, '{:title}には正の整数を入力してください。'),
			'negative_int'	=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_INT) < 1;}, '{:title}には負の整数を入力してください。'),
			'int_length'	=> array(function ($value, $options, $meta = array()) {return static::Length($value, array('length' => Arrays::AdjustArray(options, array(0, 'length'))), $options);}, '{:title}は{:length:0}桁入力してください。'),
			'int_range'		=> array(function ($value, $options, $meta = array()) {return is_int(filter_var($value, \FILTER_VALIDATE_INT, $options));}, '{:title}には{:min_range:0}から{:max_range:1}までの間の半角数値を入力してください。'),
			'int_min_range'	=> array(function ($value, $options, $meta = array()) {return is_int(filter_var($value, \FILTER_VALIDATE_INT, array('min_range' => $options['min_range'])));}, '{:title}には{:min_range:0}以上の半角数値を入力してください。'),
			'int_max_range'	=> array(function ($value, $options, $meta = array()) {return is_int(filter_var($value, \FILTER_VALIDATE_INT, array('max_range' => $options['max_range'])));}, '{:title}には{:max_range:0}以下の半角数値を入力してください。'),

			'float'			=> array(function ($value, $options, $meta = array()) {return is_float(filter_var($value, \FILTER_VALIDATE_FLOAT)) && 0 === preg_match("/\A[^0-9\-\+eEx\.]\z/", $value);}, '{:title}には実数を入力してください。'),

			//bit演算
			'bit_any'		=> array(function  ($value, $options, $meta = array()) {$value = (int) $value;return $value !== 0 && $value === ($value & Arrays::AdjustArray($options, array(0, 'bit'), 0));}, '{:title}には有効なbit値を入力してください。'),
			'bit_or'		=> array(function  ($value, $options, $meta = array()) {$value = (int) $value;return $value !== 0 && $value === ($value & Arrays::AdjustArray($options, array(0, 'bit'), 0));}, '{:title}には有効なbit値を入力してください。'),

			//型
			'is_array'		=> array(function ($value, $options, $meta = array()) {return is_array($value);}, '{:title}には配列を設定してください。'),
			'is_bool'		=> array(function ($value, $options, $meta = array()) {return is_bool($value);}, '{:title}には真偽値を設定してください。'),
			'is_callable'	=> array(function ($value, $options, $meta = array()) {return is_callable($value);}, '{:title}にはコーラブルな値を設定してください。'),
			'is_double'		=> array(function ($value, $options, $meta = array()) {return is_double($value);}, '{:title}には浮動小数点を設定してください。'),
			'is_float'		=> array(function ($value, $options, $meta = array()) {return is_float($value);}, '{:title}には浮動小数点を設定してください。'),
			'is_int'		=> array(function ($value, $options, $meta = array()) {return is_int($value);}, '{:title}には整数を設定してください。'),
			'is_integer'	=> array(function ($value, $options, $meta = array()) {return is_integer($value);}, '{:title}には整数を設定してください。'),
			'is_iterable'	=> array(function ($value, $options, $meta = array()) {return is_iterable($value);}, '{:title}にはイテレータブルな値を設定してください。'),
			'is_long'		=> array(function ($value, $options, $meta = array()) {return is_long($value);}, '{:title}には整数を設定してください。'),
			'is_null'		=> array(function ($value, $options, $meta = array()) {return is_null($value);}, '{:title}にはNULLを設定してください。'),
			'is_numeric'	=> array(function ($value, $options, $meta = array()) {return is_numeric($value);}, '{:title}には数字または数値形式の文字列を設定してください。'),
			'is_object'		=> array(function ($value, $options, $meta = array()) {return is_object($value);}, '{:title}にはオブジェクトを設定してください。'),
			'is_real'		=> array(function ($value, $options, $meta = array()) {return is_real($value);}, '{:title}には浮動小数点を設定してください。'),
			'is_resource'	=> array(function ($value, $options, $meta = array()) {return is_resource($value);}, '{:title}にはリソース型の値を設定してください。'),
			'is_scalar'		=> array(function ($value, $options, $meta = array()) {return is_scalar($value);}, '{:title}にはスカラーな値を設定してください。'),
			'is_string'		=> array(function ($value, $options, $meta = array()) {return is_string($value);}, '{:title}には文字列を設定してください。'),

			//意味
			'num'			=> array(function ($value, $options, $meta = array()) {return ctype_digit($value);}, '{:title}には数値のみ入力してください。'),
			'numeric'		=> array(function ($value, $options, $meta = array()) {return ctype_digit($value);}, '{:title}には数値のみ入力してください。'),
			'digit'			=> array(function ($value, $options, $meta = array()) {return ctype_digit($value);}, '{:title}には数値のみ入力してください。'),
			'alpha'			=> array(function ($value, $options, $meta = array()) {return ctype_alpha($value);}, '{:title}にはアルファベットのみ入力してください。'),
			'alpha_num'		=> array(function ($value, $options, $meta = array()) {return ctype_alnum($value);}, '{:title}にはアルファベットと数字のみ入力してください。'),
			'blank'			=> array("/^\s/", '{:title}には空白以外を入力しないでください。'),
			'phone'			=> array("/^\d{2,4}\-\d{4}\-\d{4}\$/", '{:title}には電話番号を入力してください。例：000-0000-0000'),

			//PHP session id
			'session_id'	=> array("/\A[,0-9a-zA-Z\-]{1,128}\z/", '{:title}にはsession idとして有効な値を入力してください。'),

			//UUID
			'uuid_v4'		=> array("/\A[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-4[0-9a-fA-F]{3}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\z/", '{:title}にはUUID v4を入力してください。'),

			//url
			'url'			=> array(function ($value, $options, $meta = array()) {return static::Url($value, $options, $meta);}, '{:title}にはURLを入力してください。例：https://example.com/ または http://example.com/'),

			//e-mail
			'email'			=> array(function ($value, $options, $meta = array()) {return is_string(filter_var($value, \FILTER_VALIDATE_EMAIL));}, '{:title}にはemailアドレスを入力してください。例：user@example.com'),
			'email_char'	=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_SANITIZE_EMAIL) === $value;}, '{:title}にはemailアドレスで使用できる文字を入力してください。'),
			'email_strict'	=> array(function ($value, $options, $meta = array()) {$separated_value = explode('@', $value);return isset($separated_value[1]) && filter_var($value, \FILTER_SANITIZE_EMAIL) === $value && checkdnsrr($separated_value[1], 'MX') && count(dns_get_record($separated_value[1], DNS_MX)) !== 0;}, '{:title}には有効なemailアドレスを入力してください。'),
			'email_include_localhost'	=> array(function ($value, $options, $meta = array()) {if (is_string(filter_var($value, \FILTER_VALIDATE_EMAIL))) {return true;};$separated_value = explode('@', $value);if (count($separated_value) !== 2 || $separated_value[1] !== 'localhost') {return false;};return is_string(filter_var($separated_value[0].'@example.com', \FILTER_VALIDATE_EMAIL));}, '{:title}には有効なemailアドレスを入力してください。'),
			'email_jp_limited'	=> array(function ($value, $options, $meta = array()) {return static::EmailJpLimited($value, $options, $meta);}, '{:title}にはemailアドレスを入力してください。例：user@example.com'),

			//IP addr
			'ip_addr'				=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_IP) === $value;}, '{:title}にはIPアドレスを入力してください。'),
			'ip_v4_addr'			=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4) === $value;}, '{:title}にはIP V4アドレスを入力してください。'),
			'ip_v6_addr'			=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6) === $value;}, '{:title}にはIP V6アドレスを入力してください。'),
			'no_private_ip_addr'	=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE) === $value;}, '{:title}にはプライベートIPアドレス以外のIPアドレスを入力してください。'),
			'no_res_ip_addr'		=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_RES_RANGE) === $value;}, '{:title}には予約済みIPアドレス以外のIPアドレスを入力してください。'),

			//ホスト
			'hostname'				=> array(function ($value, $options, $meta = array()) {return static::Hostname($value, $options, $meta);}, '{:title}には有効なホスト名を入力してください。'),
			'host'					=> array(function ($value, $options, $meta = array()) {return static::Hostname($value, $options, $meta) || filter_var($value, \FILTER_VALIDATE_IP) === $value;}, '{:title}には有効なホスト名を入力してください。'),

			//ポート
			'port'							=> array(function ($value, $options, $meta = array()) {$length = strlen($value);return $length === strspn($value, '1234567890') && -0 < $value && $value < 65536;}, '{:title}には有効なポートを入力してください。'),
			'well_known_port'				=> array(function ($value, $options, $meta = array()) {$length = strlen($value);return $length === strspn($value, '1234567890') && -0 < $value && $value < 1024;}, '{:title}には有効なポートを入力してください。'),
			'registered_port'				=> array(function ($value, $options, $meta = array()) {$length = strlen($value);return $length === strspn($value, '1234567890') && 1023 < $value && $value < 49152;}, '{:title}には有効なポートを入力してください。'),
			'dynamic_and_or_private_ports'	=> array(function ($value, $options, $meta = array()) {$length = strlen($value);return $length === strspn($value, '1234567890') && 49151 < $value && $value < 65536;}, '{:title}には有効なポートを入力してください。'),

			//DNS
			'exists_host'		=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, $options['type']);}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_mx'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'MX');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_ns'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'NS');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_soa'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'SOA');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_ptr'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'PTR');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_cname'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'CNAME');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_aaaa'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'AAAA');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_a6'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'A6');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_srv'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'SRV');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_naptr'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'NAPTR');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_naptr'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'NAPTR');}, '{:title}には存在するホスト名を入力してください。'),
			'exists_host_any'	=> array(function ($value, $options, $meta = array()) {return checkdnsrr($value, 'ANY');}, '{:title}には存在するホスト名を入力してください。'),

			'exists_dns_record_mx'	=> array(function ($value, $options, $meta = array()) {return count(dns_get_record($value, DNS_MX)) !== 0;}, '{:title}には存在するホスト名を入力してください。'),

			//範囲
			'range'			=> array(function ($value, $options, $meta = array()) {return static::Range($value, $options, Arrays::AdjustArray($options, 'format'), $options);}, '{:title}には{:min_range:0}から{:max_range:1}までの間の値を入力してください。'),
			'min_range'		=> array(function ($value, $options, $meta = array()) {return static::Range($value, array('min_range' => Arrays::AdjustArray($options, array(0, 'min_range'))), Arrays::AdjustArray($options, 'format'), $options);}, '{:title}には{:min_range:0}以上の値を入力してください。'),
			'max_range'		=> array(function ($value, $options, $meta = array()) {return static::Range($value, array('max_range' => Arrays::AdjustArray($options, array(1, 'max_range'))), Arrays::AdjustArray($options, 'format'), $options);}, '{:title}には{:max_range:0}以下の値を入力してください。'),

			//日付
			'date'			=> array(function ($value, $options, $meta = array()) {return static::DateTime($value, Arrays::AdjustArray($options, 'format', static::YMD));}, '{:title}には{:format:0}形式の日付を入力してください。'),
			'time'			=> array(function ($value, $options, $meta = array()) {return static::DateTime($value, Arrays::AdjustArray($options, 'format', static::HIS));}, '{:title}には{:format:0}形式の時間を入力してください。'),
			'datetime'		=> array(function ($value, $options, $meta = array()) {return static::DateTime($value, Arrays::AdjustArray($options, 'format', static::YMD_HIS));}, '{:title}には{:format:0}形式の日付と時間を入力してください。'),

			//文字列長さ
			'length'			=> array(function ($value, $options, $meta = array()) {return static::Length($value, array('length' => Arrays::AdjustArray($options, array(0, 'length'))), $options);}, '{:title}は{:length:0}文字入力してください。'),
			'between_length'	=> array(function ($value, $options, $meta = array()) {return static::Length($value, $options, $options);}, '{:title}は{:min_length:0}文字以上{:max_length:1}文字以内で入力してください。'),
			'max_length'		=> array(function ($value, $options, $meta = array()) {return static::Length($value, array('max_length' => Arrays::AdjustArray($options, array(0, 'max_length'))), $options);}, '{:title}は{:max_length:0}文字以内で入力してください。'),
			'min_length'		=> array(function ($value, $options, $meta = array()) {return static::Length($value, array('min_length' => Arrays::AdjustArray($options, array(0, 'min_length'))), $options);}, '{:title}は{:min_length:0}文字以上入力してください。'),

			//カラーコード
			'color_code'	=> array(function ($value, $options, $meta = array()) {return ColorCode::IsHexColorCode($value);}, '{:title}には16進数のカラーコードを入力してください。'),

			//配列
			'in'					=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_IN,					Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}に未定義の値が入力されています。'),
			'not_in'				=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_NOT_IN,				Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}の値は利用できません。'),
			'not_overlap'			=> array(function ($value, $options, $meta = array()) {$tmp = array();foreach ($value as $element) {if (in_array($element, $tmp, true)) {return false;}$tmp[] = $element;}return true;}, '{:title}に重複した値があります。'),
			'key'					=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_KEY,				Arrays::AdjustArray($options, array(0, 'key_set')), $options);}, '{:title}に未定義の値が入力されています。'),
			'key_exists'			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_KEY_EXISTS,			Arrays::AdjustArray($options, array(0, 'key_set')), $options);}, '{:title}に未定義の値が入力されています。'),
			'any'					=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_ANY,				Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}に必須項目が含まれていません。'),
			'any_key_exists'		=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_ANY_KEY_EXISTS	,	Arrays::AdjustArray($options, array(0, 'key_set')), $options);}, '{:title}には{:key_set:0}のいずれかを入力してください。'),
			'not_any_key_exists'	=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_NOT_ANY_KEY_EXISTS,	Arrays::AdjustArray($options, array(0, 'key_set')), $options);}, '{:title}には{:key_set:0}のいずれかを入力してください。'),
			//'min'
			//'max'

			//比較
			'<'				=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_LT,			Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}には{:operand:0}未満の値を入力してください。'),
			'<='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_LT_EQ,		Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}には{:operand:0}以下の値を入力してください。'),
			'>'				=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_GT,			Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}には{:operand:0}より上の値を入力してください。'),
			'>='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_GT_EQ,		Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}には{:operand:0}以上の値を入力してください。'),
			'=='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_EQ,			Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}が{:operand:0}と異なります。'),
			'!='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_NOT_EQ,		Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}が{:operand:0}と同じです。'),
			'==='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_S_EQ,		Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}が{:operand:0}と異なります。'),
			'!=='			=> array(function ($value, $options, $meta = array()) {return static::Comparison($value, static::OP_S_NOT_EQ,	Arrays::AdjustArray($options, array(0, 'operand')), $options);}, '{:title}が{:operand:0}と同じです。'),

			//ファイルシステム
			'file_exists'	=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return file_exists($value);}, 'パス：{:value}は存在しません。'),
			'is_dir'		=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return is_dir($value);}, 'パス：{:value}はディレクトリではありません。'),
			'is_file'		=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return is_file($value);}, 'パス：{:value}はファイルではありません。'),
			'readable'		=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return is_readable($value);}, 'パス：{:value}は読み込めません。'),
			'writable'		=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return is_writable($value);}, 'パス：{:value}は書き込めません。'),
			'executable'	=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return is_executable($value);}, 'パス：{:value}は実行できません。'),
//			'file_size'		=> array(function ($value, $options, $meta = array()) {clearstatcache(true, $value);return filesize($value);}, 'パス：{:value}は存在しません。'),

			'parent_is_dir'		=> array(function ($value, $options, $meta = array()) {$value = dirname($value);clearstatcache(true, $value);return is_dir($value);}, 'パス：{:value}の親はディレクトリではありません。'),
			'parent_exists'		=> array(function ($value, $options, $meta = array()) {$value = dirname($value);clearstatcache(true, $value);return file_exists($value);}, 'パス：{:value}の親ディレクトリがありません。'),
			'parent_executable'	=> array(function ($value, $options, $meta = array()) {$value = dirname($value);clearstatcache(true, $value);return strtolower(substr(\PHP_OS, 0, 3)) === 'win' ? is_readable($value) : is_executable($value);}, 'パス：{:value}の親ディレクトリを開けません。'),
			'parent_readable'	=> array(function ($value, $options, $meta = array()) {$value = dirname($value);clearstatcache(true, $value);return is_readable($value);}, 'パス：{:value}の親ディレクトリを読み込めません。'),
			'parent_writable'	=> array(function ($value, $options, $meta = array()) {$value = dirname($value);clearstatcache(true, $value);return is_writable($value);}, 'パス：{:value}の親ディレクトリに書き込めません。'),

			//ファイルアップロード
			'upload_check_status'	=> array(function ($value, $options, $meta = array()) {return static::CheckUploadStatus($value, $options, $meta);}, '{:title}{:adjust}でエラーが発生しました。error code:{:error_code} {:validator_message}'),
			'upload_range_filesize'	=> array(function ($value, $options, $meta = array()) {return static::Range($value['size'], $options, Arrays::AdjustArray($options, 'format'), $options);}, '{:title}はファイルサイズを{:min_range:0}バイトから{:max_range:1}バイトまでの間にしてください。'),
			'upload_min_filesize'	=> array(function ($value, $options, $meta = array()) {return static::Range($value['size'], array('min_range' => Arrays::AdjustArray($options, array(0, 'min_range'))), Arrays::AdjustArray($options, 'format'), $options);}, '{:title}はファイルサイズが{:min_range:0}バイト以上必要です。'),
			'upload_max_filesize'	=> array(function ($value, $options, $meta = array()) {return static::Range($value['size'], array('max_range' => Arrays::AdjustArray($options, array(1, 'max_range'))), Arrays::AdjustArray($options, 'format'), $options);}, '{:title}はファイルサイズが{:max_range:0}バイト以下である必要があります。'),
			'upload_mimetype'		=> array(function ($value, $options, $meta = array()) {return $value['type'] > Arrays::AdjustArray($options, array(0, 'max'));} ,'{:title}は{:max:0}バイト以上にしてください。'),
			'upload_ext'			=> array(function ($value, $options, $meta = array()) {return $value['type'] > Arrays::AdjustArray($options, array(0, 'max'));} ,'{:title}は{:max:0}バイト以上にしてください。'),
			'upload_name'			=> array(function ($value, $options, $meta = array()) {return $value['type'] > Arrays::AdjustArray($options, array(0, 'max'));} ,'{:title}は{:max:0}バイト以上にしてください。'),

			//文字セット
			'charset_email'			=> array(function ($value, $options, $meta = array()) {$filterd_length = strlen(filter_var($value, \FILTER_SANITIZE_EMAIL));return $filterd_length !== 0 && $filterd_length === strlen($value);}, '{:title}にはemailに利用できる文字を入力してください。'),
			'charset_full_kana'		=> array(function ($value, $options, $meta = array()) {return 1 === preg_match(sprintf("/^[ァ-ヶぁ-ん%s]+$/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value);}, '{:title}に利用できない文字「{:reject_character:0}」が含まれています。', array('reject_character' => function ($value, $options, $meta = array()) {preg_match_all(sprintf("/([^ァ-ヶぁ-ん%s])/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value, $reject_character);return implode(', ', array_unique($reject_character[1]));}),),
			'charset_full_katakana'	=> array(function ($value, $options, $meta = array()) {return 1 === preg_match(sprintf("/^[ァ-ヶ%s]+$/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value);}, '{:title}に利用できない文字「{:reject_character:0}」が含まれています。', array('reject_character' => function ($value, $options, $meta = array()) {preg_match_all(sprintf("/([^ァ-ヶ%s])/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value, $reject_character);return implode(', ', array_unique($reject_character[1]));}),),
			'charset_full_hiragana'	=> array(function ($value, $options, $meta = array()) {return 1 === preg_match(sprintf("/^[ぁ-ん%s]+$/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value);}, '{:title}に利用できない文字「{:reject_character:0}」が含まれています。', array('reject_character' => function ($value, $options, $meta = array()) {preg_match_all(sprintf("/([^ぁ-ん%s])/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value, $reject_character);return implode(', ', array_unique($reject_character[1]));}),),
			'charset_full_alpha'	=> array(function ($value, $options, $meta = array()) {return 1 === preg_match(sprintf("/^[ａ-ｚＡ-Ｚ%s]+$/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value);}, '{:title}に利用できない文字「{:reject_character:0}」が含まれています。', array('reject_character' => function ($value, $options, $meta = array()) {preg_match_all(sprintf("/([^ａ-ｚＡ-Ｚ%s])/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value, $reject_character);return implode(', ', array_unique($reject_character[1]));}),),
			'charset_full_num'		=> array(function ($value, $options, $meta = array()) {return 1 === preg_match(sprintf("/^[０-９%s]+$/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value);}, '{:title}に利用できない文字「{:reject_character:0}」が含まれています。', array('reject_character' => function ($value, $options, $meta = array()) {preg_match_all(sprintf("/([^０-９%s])/u", (isset($options['append_pattern']) ? $options['append_pattern'] : '')), $value, $reject_character);return implode(', ', array_unique($reject_character[1]));}),),

			//エンコーディング
			'utf8'			=> array(function ($value, $options, $meta = array()) {return static::Encoding($value, array('encoding' => 'UTF-8') + $options);}, '{:title}がUTF-8ではなく{:encoding}になっています。'),
			'sjis-win'		=> array(function ($value, $options, $meta = array()) {return static::Encoding($value, array('encoding' => 'SJIS-win') + $options);}, '{:title}がSJIS-winではなく{:encoding}になっています。'),
			'eucjp-win'		=> array(function ($value, $options, $meta = array()) {return static::Encoding($value, array('encoding' => 'eucJP-win') + $options);}, '{:title}がeucJP-winではなく{:encoding}になっています。'),

			//PREG 互換正規表現
			'preg_regex'	=> array(function ($value, $options, $meta = array()) {return filter_var($value, \FILTER_VALIDATE_REGEXP) === $value;}, '{:title}にはPREG互換の正規表現を入力してください。'),

			//正規表現
			'regex'			=> array(function ($value, $options, $meta = array()) {return preg_match(Arrays::AdjustArray($options, array(0, 'regex')), $value) === 1;}, '{:title}がパターンに一致しません。'),

			//クレジットカード
			'luhn'			=> array(function ($value, $options, $meta = array()) {for ($i = 0, $digits = strrev($digits), $alt = true, $total = 0; ($str = substr($digits, $i, 1)) !== false;$total += $alt ? $str : ($str < 5 ? $str * 2 : 1 + ($str - 5) * 2), $alt = !$alt, $i++); return $total % 10 === 0;}, '{:title}のチェックディジットが正しくありません。'),
			'credit_card'	=> array(function ($value, $options, $meta = array()) {return static::CreditCard($value, $options, $meta);}, '{:title}のクレジットカード番号が正しくありません。'),

			//パディング
			'padding'		=> array(function ($value, $options, $meta = array()) {return $value === str_pad($value, $options['length'], $options['char'], $options['vector']);}, '{:title}の値が正しくありません。'),
			'zero_padding'	=> array(function ($value, $options, $meta = array()) {return $value === str_pad($value, $options['length'], '0', \STR_PAD_LEFT);}, '{:title}の値が正しくありません。'),

			//HTML
			'html'				=> array(function ($value, $options, $meta = array()) {return static::Html($value, Arrays::AdjustArray($options, array(0, 'value')), $options);}, '{:title}に利用できない{:validator_message}が含まれています。'),
			'html_element'		=> array(function ($value, $options, $meta = array()) {return static::HtmlElement($value, Arrays::AdjustArray($options, array(0, 'value')), $options);}, '{:title}に利用できないHTML要素 {:validator_message}が含まれています。'),
			'html_tag'			=> array(function ($value, $options, $meta = array()) {return static::HtmlElement($value, Arrays::AdjustArray($options, array(0, 'value')), $options);}, '{:title}に利用できないHTMLタグ {:validator_message}が含まれています。'),
			'html_attribute'	=> array(function ($value, $options, $meta = array()) {return static::HtmlAttribute($value, Arrays::AdjustArray($options, array(0, 'value')), $options);}, '{:title}に利用できないHTML属性 {:validator_message}が含まれています。'),
			'html_attr'			=> array(function ($value, $options, $meta = array()) {return static::HtmlAttribute($value, Arrays::AdjustArray($options, array(0, 'value')), $options);}, '{:title}に利用できないHTML属性 {:validator_message}が含まれています。'),

			//コールバック
			'callback'		=> array(function ($value, $options, $meta = array()) {return static::Callback($value, $options, $meta);}, ''),
		);
	}

	/**
	 * datetime date time rule時の処理
	 *
	 * @param	mixed	$value		検証する値
	 * @param	array	$options	オプション
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 */
	 public static function DateTime ($value, $format) {
		try {
			$dateTime = new \DateTime($value);
			return $dateTime->format($format) === $value;
		} catch (\Exception $e) {
			return false;
		}
	}

	/**
	 * Hostname check
	 */
	public static function Hostname ($value, $options = array()) {
		$length = strlen($value);
		if ($length > 255) {
			return false;
		}
		if ($length !== strspn($value, 'abcdefghijklmnopqrstuvwxyzABCEDFGHIJKLMNOPQRSTUVWXYZ1234567890-.')) {
			return false;
		}
		if ($length === strspn($value, '1234567890.')) {
			return false;
		}
		if ($length === strspn($value, 'abcdefghijklmnopqrstuvwxyz1234567890.:')) {
			return false;
		}

		foreach(explode('.', $value) as $label) {
			$label_length = strlen($label);
			if ($label_length === 0) {
				return false;
			}
			if ($label_length > 63) {
				return false;
			}
			if (substr($label, -1) === '-') {
				return false;
			}
		}
		return true;
	}

	/**
	 * Encoding check
	 */
	public static function Encoding ($value, $options = array()) {
		$detect_encoding = static::DetectEncoding($value, $options);
		return $detect_encoding === $options['encoding'] || $detect_encoding === 'ASCII';
	}

	/**
	 * Detect encoding
	 */
	public static function DetectEncoding ($value, $options = array()) {
		return mb_detect_encoding($value, isset($options['detect_order']) ? $options['detect_order'] : array('UTF-8', 'SJIS-win', 'eucJP-win', 'JIS', 'ASCII'), true);
	}

	/**
	 * Credit card check
	 */
	public static function CreditCard ($value, $options) {
		//
		$number_pattern_list	= array(
			'American Express'	=> array(
				"/^34[0-9]{13}$/",
				"/^37[0-9]{13}$/",
			),
			'China UnionPay'	=> array(
				"/^62212[6-9][0-9]{10}$/",
				"/^6221[3-9][0-9][0-9]{10}$/",
				"/^622[2-8] [0-9]{12}$/",
				"/^6229[01][0-9][0-9]{10}$/",
				"/^62292[0-5][0-9]{10}$/",
				"/^62[4-6][0-9]{13}$/",
				"/^628[2-8][0-9]{12}$/",
			),
			'Diners Club International'	=> array(
				"/^300[0-9]{11}$/",
				"/^305[0-9]{11}$/",
				"/^3095[0-9]{10}$/",
				"/^36[0-9]{11}$/",
				"/^3[89][0-9]{12}$/",
			),
			'Discover Card'	=> array(
				"/^60110[0-9]{11}$/",
				"/^6011[2-4][0-9]{11}$/",
				"/^60117[4-9][0-9]{10}$/",
				"/^60118[6-9][0-9]{10}$/",
				"/^60119[0-9][0-9]{10}$/",
				"/^64[4-9][0-9]{13}$/",
				"/^65[0-9]{14}$/",
			),
			'JCB'	=> array(
				"/^352[89][0-9]{12}$/",
				"/^35[3-7][0-9]{12}$/",
				"/^358[1-9][0-9]{12}$/",
			),
			'MasterCard'	=> array(
				"/^5[0-9]{15}$/",
			),
			'UATP'			=> array(
				"/^1[0-9]{14}$/",
			),
			'Visa'			=> array(
				"/^4[0-9]{13}(?:[0-9]{3})?$/",
			),
		);

		foreach ($number_pattern_list as $card_name => $pattern_list) {
			foreach ($pattern_list as $pattern) {
				if (1 === preg_match($pattern, $value)) {
					//チェックディジット
					for ($i = 0, $value = strrev($value), $alt = true, $total = 0; ($str = substr($value, $i, 1)) !== false;$total += $alt ? $str : ($str < 5 ? $str * 2 : 1 + ($str - 5) * 2), $alt = !$alt, $i++);
					return $total % 10 === 0;
				}
			}
		}

		return false;
	}

	/**
	 * Length check
	 *
	 * @param	mixed	$value		検証する値
	 * @param	array	$options	オプション
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 */
	public static function Length ($value, $length_set, $options) {
		$filter = Arrays::AdjustArray($options, 'filter');
		if (is_callable($filter)) {
			$value = $filter($value);
		}

		if (!is_array($value)) {
			$encoding = Arrays::AdjustArray($length_set, 'encoding', Encoding::DEFAULT_ENCODING);
			$string_length = Strings::Length($value, $encoding);
		} else {
			$string_length = count($value);
		}

		if (($length = Arrays::AdjustArray($length_set, 'length')) !== null) {
			return $string_length === $length;
		}

		$min_length = Arrays::AdjustArray($length_set, array(0, 'min_length'));
		$max_length = Arrays::AdjustArray($length_set, array(1, 'max_length'));

		if ($min_length === null) {
			return $string_length <= $max_length;
		}

		if ($max_length === null) {
			return $min_length <= $string_length;
		}

		return ($min_length <= $string_length && $string_length <= $max_length);
	}

	/**
	 * Range Check
	 *
	 * @param	mixed	$value		検証する値
	 * @param	array	$range_set	長さセット
	 * @param	string	$type		検証値の型
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 */
	public static function Range ($value, $range_set, $type = null, $options = array()) {
		$min_range= Arrays::AdjustArray($range_set, array(0, 'min_range'));
		$max_range= Arrays::AdjustArray($range_set, array(1, 'max_range'));

		$converter = static::GetConverter($type);

		if (is_callable($converter)) {
			if ($min_range !== null) {
				$min_range = $converter($min_range);
			}
			if ($max_range !== null) {
				$max_range = $converter($max_range);
			}
			$value = $converter($value);
		}

		if ($min_range === null) {
			return $value <= $max_range;
		}

		if ($max_range === null) {
			return $min_range <= $value;
		}

		return ($min_range <= $value && $value <= $max_range);
	}

	/**
	 * Comparison check
	 *
	 * @param	mixed	$value		検証する値
	 * @param	string	$operator	演算子
	 * @param	array	$options	オプション
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 */
	public static function Comparison ($value, $operator, $operand, $options) {
		$converter = static::GetConverter(Arrays::AdjustArray($options, 'type'));
		if (is_callable($converter)) {
			$value		= $converter($value);
			$operand	= $converter($operand);
		}

 		if (is_object($value) && is_callable($value)) {
 			$value = $value($operator, $operand, $options);
 		}

 		if (is_object($operand) && is_callable($operand)) {
 			$operand = $operand($operator, $operand, $options);
 		}

		if (($empty_skip_type = Arrays::AdjustArray($options, 'have_to_skip', false)) !== false) {
			if (static::TwoValueEmptyChecker($value, $operand, $empty_skip_type, Arrays::AdjustArray($options, 'empty_filter'))) {
				return true;
			}
		}

		switch ($operator) {
			case static::OP_LT:
				return $value < $operand;
			case static::OP_LT_EQ:
				return $value <= $operand;
			case static::OP_GT:
				return $value > $operand;
			case static::OP_GT_EQ:
				return $value >= $operand;
			case static::OP_EQ:
				return $value == $operand;
			case static::OP_NOT_EQ:
				return $value != $operand;
			case static::OP_S_EQ:
				return $value === $operand;
			case static::OP_S_NOT_EQ:
				return $value !== $operand;
			case static::OP_IN:
				return in_array($value, Arrays::AdjustArray($operand), true);
			case static::OP_ANY:
				$ret = array_intersect(Arrays::AdjustArray($value), Arrays::AdjustArray($operand));
				return !empty($ret);
			case static::OP_NOT_IN:
				return !in_array($value, Arrays::AdjustArray($operand), true);
			case static::OP_KEY_EXISTS:
			case static::OP_KEY:
				return isset($operand[$value]) || array_key_exists($value, $operand);
			case static::OP_ANY_KEY_EXISTS:
				foreach ((array) $operand as $needle) {
					if (isset($value[$needle]) || array_key_exists($needle, $value)) {
						return true;
					}
				}
				return false;
			case static::OP_NOT_ANY_KEY_EXISTS:
				$count = 0;
				foreach ((array) $operand as $needle) {
					if (isset($value[$needle]) || array_key_exists($needle, $value)) {
						if (++$count > 1) {
							return false;
						}
					}
				}
				return true;
			default:
				return false;
		}
	}

	/**
	 * エンプティラッパー指定時のラップ処理を行います。
	 *
	 * @param	mixed	$value	判定する値
	 * @return	mixed	判定された値
	 */
	public static function WrappingEmptyFunction ($value) {
		return !($value === 0 || $value === 0.0 || $value === '0' || !empty($value));
	}

	/**
	 * 左辺値、右辺値ともに空かどうかを判定します。
	 *
	 * @param	mixed		$left_value		左辺値
	 * @param	mixed		$right_value	右辺値
	 * @param	string		$type			値の型
	 * @param	callable	$filter			フィルタ
	 * @return	bool		左辺値、右辺値ともに空でなければtrue、そうでなければfalse
	 */
	public static function TwoValueEmptyChecker ($left_value, $right_value, $type, $filter = null) {
		if (!is_callable($filter)) {
			$filter = array(get_called_class(), 'WrappingEmptyFunction');
		}

		switch ($type) {
			case 'whichever':
				return $filter($left_value) || $filter($right_value);
			case 'left_value':
				return $filter($left_value);
			case 'right_value':
				return $filter($right_value);
			case 'both':
				$type === true;
		}
		return ($type === true && $filter($left_value) && $filter($right_value));
	}

	/**
	 * コンバータを返します。
	 *
	 * @param	string		$type	型
	 * @return	callable	コンバータコールバック
	 */
	public static function GetConverter ($type) {
		if (!is_callable($type)) {
			switch ($type ?: 'none') {
				case 'datetime':
					$type = function ($value) {
						if ($value === '' || $value === null) {
							return $value;
						}
						return new \DateTime($value);
					};
					break;
			}
		}
		return $type;
	}

	/**
	 * 日本国内のみで流通しているRFC違反メールアドレスを許した上でemail addressとしての妥当性の検証を行います。
	 *
	 * @param	mixed	$value		検証する値
	 * @param	array	$options	オプション
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 */
	public static function EmailJpLimited ($value, $options) {
		if (filter_var($value, \FILTER_SANITIZE_EMAIL) !== $value) {
			return false;
		}
		$part = explode('@', $value, 2);
		$part[0] = preg_replace_callback("/(\.{2,}|\-{2,}|_{2,})/", function ($mat) {return str_repeat('a', strlen($mat[1]));}, $part[0]);
		if (substr($part[0], -1, 1) === '.') {
			$part[0] = substr($part[0], 0, -1) . 'a';
		}
		return is_string(filter_var(implode('@', $part), \FILTER_VALIDATE_EMAIL));
	}

	public static function Url ($value, $options, $meta = array()) {
		if (false === filter_var($value, \FILTER_VALIDATE_URL, \FILTER_FLAG_SCHEME_REQUIRED | \FILTER_FLAG_HOST_REQUIRED | (Arrays::AdjustArray($options, array('filter', '0'), 0)))) {
			return false;
		}

		$ret = parse_url($value);
		$scheme = Arrays::AdjustArray($ret, 'scheme', '');
		if ($scheme !== 'http' && $scheme !== 'https') {
			return false;
		}

		$host = Arrays::AdjustArray($ret, 'host', '');
		if (!static::Hostname($host) && filter_var($host, \FILTER_VALIDATE_IP) !== $host) {
			return false;
		}

		$accept_host = (array) (Arrays::AdjustArray($options, array('accept_host', 0, 'localhost')));
		if (in_array($host, $accept_host, true)) {
			return true;
		}

		$accept_pattern_list = (array) (Arrays::AdjustArray($options, 'accept_pattern', array()));
		foreach ($accept_pattern_list as $accept_pattern) {
			if (preg_match(sprintf("@\A%s\z@", $accept_pattern), $host) === 1) {
				return true;
			}
		}

		if (false === $dot_pos = strrpos($host, '.')) {
			return false;
		}

		$top_level_domain_list = DomainUtility::topLevelDomainList();
		if (!isset($top_level_domain_list[substr($host, $dot_pos + 1)])) {
			return false;
		}

		return true;
	}

	/**
	 * HTML文字列中に指定された要素と属性の組み合わせが存在しないか検証を行います。
	 */
	public static function Html ($value, $targets, $options = array()) {
		$encoding	= Arrays::AdjustArray($options, 'encoding', mb_internal_encoding());

		$result = array();

		$html = sprintf('<?xml version="1.0" encoding="%s"?><root>%s</root>', $encoding, $value);

		$dom = new \DOMDocument;

		libxml_use_internal_errors(true);
		$dom->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'));
		libxml_clear_errors();

		$elements_cache = array();

		if (isset($targets['*'])) {
			$elements = $dom->getElementsByTagName('*');
			foreach ($elements as $element) {
				if (!isset($elements_cache[$element->tagName])) {
					$elements_cache[$element->tagName] = $elements;
				}
				foreach ((array) $targets['*'] as $attr) {
					if ($element->hasAttribute($attr)) {
						$result['attr'][$attr] = $attr;
					}
				}
			}
			unset($targets['*']);
		}

		foreach ($targets as $tag => $attrs) {
			if (is_int($tag)) {
				foreach ((array) $attrs as $tag) {
					$elements_cache[$tag] = Arrays::AdjustArray($elements_cache, $tag, $dom->getElementsByTagName($tag));
					if ($elements_cache[$tag]->length> 0) {
						$result['tag'][$tag] = $tag;
					}
				}

				continue;
			}

			$elements_cache[$tag] = Arrays::AdjustArray($elements_cache, $tag, $dom->getElementsByTagName($tag));
			if ($elements_cache[$tag]->length > 0) {
				foreach ((array) $attrs as $attr) {
					foreach ($elements_cache[$tag] as $element) {
						if ($element->hasAttribute($attr)) {
							$result['html'][$tag][$attr] = $attr;
						}
					}
				}
			}
		}

		$string = array();
		if (isset($result['html'])) {
			foreach ($result['html'] as $tag => $attrs) {
				$result['html'][$tag] = sprintf('%s => %s', $tag, implode(', ', $attrs));
			}
			$string['html'] = sprintf('HTML要素と属性の組み合わせ %s', implode(', ', $result['html']));
		}

		if (isset($result['tag'])) {
			$string['tag'] = sprintf('HTML要素 %s', implode(', ', $result['tag']));
		}

		if (isset($result['attr'])) {
			$string['attr'] = sprintf('HTML属性 %s', implode(', ', $result['attr']));
		}

		return empty($result) ?: implode(', ', $string);
	}

	/**
	 * HTML文字列中に指定された要素が存在しないか検証を行います。
	 */
	public static function HtmlElement ($value, $targets, $options = array()) {
		$encoding	= Arrays::AdjustArray($options, 'encoding', mb_internal_encoding());

//		$html = static::SanitizeControlCode($html);
//		$html = static::SanitizeUnicodeControlCode($html);

		$html = sprintf('<?xml version="1.0" encoding="%s"?><root>%s</root>', $encoding, $value);

		$dom = new \DOMDocument;

		libxml_use_internal_errors(true);
		$dom->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'));
		libxml_clear_errors();

		$result = array();
		foreach ($targets as $target) {
			if ($dom->getElementsByTagName($target)->length > 0) {
				$result[$target] = $target;
			}
		}

		return empty($result) ?: implode(', ', $result);
	}

	/**
	 * HTML文字列中に指定された属性が存在しないか検証を行います。
	 */
	public static function HtmlAttribute ($value, $targets, $options = array()) {
		$encoding	= Arrays::AdjustArray($options, 'encoding', mb_internal_encoding());

		$html = sprintf('<?xml version="1.0" encoding="%s"?><root>%s</root>', $encoding, $value);

		$dom = new \DOMDocument;

		libxml_use_internal_errors(true);
		$dom->loadHTML(mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8'));
		libxml_clear_errors();

		$result = array();
		foreach ($dom->getElementsByTagName('*') as $element) {
			foreach ($targets as $target) {
				if ($element->hasAttribute($target)) {
					$result[$target] = $target;
				}
			}
		}

		return empty($result) ?: implode(', ', $result);
	}

	public static function CheckUploadStatus ($value, $options, $meta = array()) {
		$error_code = Arrays::AdjustArray($value, 'error');
		if ($error_code === \UPLOAD_ERR_OK) {
			return true;
		}

		$upload_error_list = array(
			\UPLOAD_ERR_INI_SIZE	=> 'アップロードされたファイルは、php.ini の upload_max_filesize ディレクティブの値を超えています。',
			\UPLOAD_ERR_FORM_SIZE	=> 'アップロードされたファイルは、HTML フォームで指定された MAX_FILE_SIZE を超えています。',
			\UPLOAD_ERR_PARTIAL		=> 'アップロードされたファイルは一部のみしかアップロードされていません。',
			\UPLOAD_ERR_NO_FILE		=> 'ファイルはアップロードされませんでした。',
			\UPLOAD_ERR_NO_TMP_DIR	=> 'テンポラリフォルダがありません。',
			\UPLOAD_ERR_CANT_WRITE	=> 'ディスクへの書き込みに失敗しました。',
			\UPLOAD_ERR_EXTENSION	=> 'PHPの拡張モジュールがファイルのアップロードを中止しました。',
		);

		return array(
			'adjust'			=> Arrays::AdjustArray($options, 'is_array', false) ? 'の{:loop_index}個目のファイル' : '',
			'error_code'		=> $error_code,
			'validator_message'	=> Arrays::AdjustArray($upload_error_list, $error_code, '不明なエラーが発生しました。'),
		);
	}
}
