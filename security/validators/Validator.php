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

namespace ickx\fw2\security\validators;

use ickx\fw2\core\exception\CoreException;
use ickx\fw2\international\encoding\Encoding;
use ickx\fw2\vartype\arrays\Arrays;

/**
 * 検証クラスです。
 *
 * @category	Flywheel2
 * @package		security
 * @author		wakaba <wakabadou@gmail.com>
 * @license		http://opensource.org/licenses/MIT The MIT License MIT
 * @varsion		2.0.0
 */
class Validator extends classes\ValidateTrait implements \ickx\fw2\date_time\interfaces\IDateTimeConst {
	//==============================================
	//Const
	//==============================================
	const CONFIG_PREFIX				= 'prefix';
	const CONFIG_SAFIX				= 'safix';
	const CONFIG_VARS				= 'vars';
	const CONFIG_TITLE				= 'title';
	const CONFIG_NAME				= 'name';
	const CONFIG_NULL_SKIP			= 'null_skip';
	const CONFIG_EMPTY_SKIP			= 'empty_skip';
	const CONFIG_STRING_EMPTY_SKIP	= 'string_empty_skip';
	const CONFIG_SKIP				= 'skip';
	const CONFIG_CALLBACK_SKIP		= 'callback_skip';
	const CONFIG_VALUE				= 'value';
	const CONFIG_FETCH_FROM_KEYS	= 'fetch_from_keys';
	const CONFIG_FETCH_ALL			= 'fetch_all';
	const CONFIG_FORCE_USE_VALUE	= 'force_use_value';
	const CONFIG_FILTER				= 'filter';
	const CONFIG_FORCE_VALIDATE		= 'force_validate';
	const CONFIG_FORCE_ERROR		= 'force_error';
	const CONFIG_RAISE_EXCEPTION	= 'raise_exception';
	const CONFIG_IS_LAST			= 'is_last';
	const CONFIG_PREMISE			= 'premise';
	const CONFIG_USE_CURRENT_DATA	= 'use_current_data';
	const CONTIG_SET_VALIDATE_TYPE	= 'set_validate_type';
	const CONFIG_VALIDATE_SET		= 'validate_set';
	const CONFIG_STOP_AFTER			= 'stop_after';
	const CONFIG_RULES				= 'rules';

	const RULE_REQUIRE				= 'require';
	const RULE_NOT_EMPTY			= 'not_empty';
	const RULE_NOT_STRING_EMPTY		= 'not_string_empty';
	const RULE_NOT_REQUIRE			= 'not_require';
	const RULE_CALLBACK				= 'callback';
	const RULE_IS_ARRAY				= 'is_array';

	const OPTION_RAISE_EXCEPTION	= 'raise_exception';
	const OPTION_IS_LAST			= 'is_last';
	const OPTION_NOT_DEAL_ARRAY		= 'not_deal_array';
	const OPTION_EMPTY_SKIP			= 'empty_skip';
	const OPTION_SEE_ARRAY_KEYS		= 'array_keys';
	const OPTION_FORCE_VALLIDATE	= 'force_validate';
	const OPTION_PREMISE			= 'premise';

	const OP_LT						= '<';
	const OP_LT_EQ					= '<=';
	const OP_GT						= '>';
	const OP_GT_EQ					= '>=';
	const OP_EQ						= '==';
	const OP_NOT_EQ					= '!=';
	const OP_S_EQ					= '===';
	const OP_S_NOT_EQ				= '!==';

	const OP_IN						= 'in';
	const OP_KEY					= 'key';
	const OP_KEY_EXISTS				= 'key_exists';
	const OP_ANY					= 'any';
	const OP_ANY_KEY_EXISTS			= 'any_key_exists';
	const OP_NOT_ANY_KEY_EXISTS		= 'not_any_key_exists';
	const OP_NOT_IN					= 'not in';

	/**
	 * コンストラクタ
	 */
	private final function __construct () {}

	//==============================================
	//Validation
	//==============================================
	/**
	 * Ruleを実行し検証の可否を返します。
	 *
	 * @param	string	$rule_name	検証ルール名
	 * @param	string	$value		検証する値
	 * @param	array	$options	オプション
	 * @param	array	$meta		メタ情報
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合
	 */
	public static function Rule ($rule_name, $value, $options = array(), $meta = array()) {
		$rule_list = static::GetValidateRuleList();
		if ($rule = Arrays::AdjustValue($rule_list, $rule_name)) {
			return (is_callable($rule[0]) || is_array($rule[0])) ? $rule[0]($value, $options, $meta) : preg_match($rule[0], $value) === 1;
		}
		throw CoreException::RaiseSystemError('Validation not found. Rule name:%s', array($rule_name));
	}

	/**
	 * 検証を行い、検証に失敗した要素についてはメッセージをリストで返します。
	 *
	 * @param	mixed	$data			検証対象データ
	 * @param	array	$data_rule_list	検証ルールリスト
	 * @param	mixed	$data_name		検証対象名
	 * @param	array	$before_errors	先行検証分のエラーリスト
	 * @param	array	$meta			メタ情報
	 * @return	mixed	検証に合格した場合:null、検証に失敗した場合:エラーメッセージの入ったリスト
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合
	 */
	public static function Check ($data, $rule_list, $data_name = 0, $before_errors = array(), $meta = array()) {
		$ret = static::BulkCheck(array($data_name => $data), array($data_name => $rule_list), $before_errors, $meta);
		$ret = array_pop($ret);
		return $ret['message'];
	}

	/**
	 * 一括で検証を行い、検証に失敗した要素についてはメッセージをリストで返します。
	 *
	 * @param	array	$data				検証対象データ
	 * @param	array	$data_rule_list		検証ルールリスト
	 * @param	array	$before_errors		先行検証分のエラーリスト
	 * @param	array	$meta				チェック実行時のメタ情報
	 * @return	array	検証に合格した場合:[]、検証に失敗した場合:エラーリスト
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合
	 */
	public static function BulkCheck ($data, $data_rule_list, $before_errors = array(), $meta = array()) {
		//==============================================
		//初期化
		//==============================================
		$errors = array();
		$error_message_list = array();

		$option_set = static::GetOptionSet();

		//==============================================
		//ルールセットごとに処理を行う
		//==============================================
		foreach ($data_rule_list as $data_name => $rule_list) {
			//==============================================
			// rulesに入れていたものをフラット化する
			//==============================================
			if (isset($rule_list[static::CONFIG_RULES])) {
				$rule_list = array_merge($rule_list, $rule_list[static::CONFIG_RULES]);
			}

			//==============================================
			// 特殊系対応
			//==============================================
			$is_upload_file = Arrays::AdjustValue($rule_list, 'source') === 'upload';

			//==============================================
			//ルールごとの初期化
			//==============================================
			//ルールリストの初期化：未設定の場合、not_emptyのみ設定されたものと見なす
			$rule_list = is_string($rule_list) ? array(static::RULE_NOT_EMPTY) : $rule_list;

			//強制検証フラグが有効な場合、フラグを変数化する
			$config_force_validate = Arrays::AdjustValue($rule_list, static::CONFIG_FORCE_VALIDATE, false);

			//強制上書きフラグの取得
			$config_force_use_value = Arrays::AdjustValue($rule_list, static::CONFIG_FORCE_USE_VALUE, false);

			//対象データの取得：フォースバリューが設定されている場合は強制上書き
			$target_value = $is_upload_file ? static::AdjustUploadFile($data, $data_name) : (Arrays::AdjustValue($data, $data_name));

			if (isset($rule_list[static::CONFIG_USE_CURRENT_DATA]) && static::CONFIG_USE_CURRENT_DATA) {
				$target_value = array($data_name => $data);
				$rule_list[static::CONFIG_FORCE_VALIDATE] = true;
			}

			if ($config_force_use_value || ($target_value === null && isset($rule_list[static::CONFIG_VALUE]))) {
				$target_value = isset($rule_list[static::CONFIG_VALUE]) ? array($rule_list[static::CONFIG_VALUE]) : null;
				$rule_list[static::CONFIG_FORCE_VALIDATE] = true;
			}

			if (isset($rule_list[static::CONFIG_FETCH_FROM_KEYS])) {
				$target_value = array();
				foreach ((array) $rule_list[static::CONFIG_FETCH_FROM_KEYS] as $name) {
					$target_value[$name] = $data[$name];
				}
				$rule_list[static::CONFIG_FORCE_VALIDATE] = true;
			}

			if (isset($rule_list[static::CONFIG_FETCH_ALL])) {
				$target_value = $data;
				$rule_list[static::CONFIG_FORCE_VALIDATE] = true;
			}

			//フィルタが有効な場合はフィルタをかける
			if (($filter = Arrays::AdjustValue($rule_list, static::CONFIG_FILTER)) && is_callable($filter)) {
				$target_value = $filter($target_value);
			}

			//NULL時スキップフラグがある場合は次のデータへ
			if ((Arrays::AdjustValue($rule_list, static::CONFIG_NULL_SKIP)) && !static::Rule(static::RULE_REQUIRE, $target_value)) {
				continue;
			}

			//空白時スキップフラグがある場合は次のデータへ
			if (isset($rule_list[static::CONFIG_EMPTY_SKIP]) && $rule_list[static::CONFIG_EMPTY_SKIP] === true && !static::Rule(static::RULE_NOT_EMPTY, $target_value)) {
				continue;
			}

			//空白時（ブランク有効）スキップフラグがある場合は次のデータへ
			if (isset($rule_list[static::CONFIG_STRING_EMPTY_SKIP]) && $rule_list[static::CONFIG_STRING_EMPTY_SKIP] === true && !static::Rule(static::RULE_NOT_STRING_EMPTY, $target_value)) {
				continue;
			}

			//プログラマブルスキップフラグがある場合は次のデータへ
			if ($func = isset($rule_list[static::CONFIG_CALLBACK_SKIP]) && $rule_list[static::CONFIG_CALLBACK_SKIP] !== true && !static::Rule(static::RULE_CALLBACK, $target_value, array($func))) {
				continue;
			}

			//スキップフラグがある場合は次のデータへ
			if (isset($rule_list[static::CONFIG_SKIP]) && $rule_list[static::CONFIG_SKIP]) {
				continue;
			}

			//プレミスフラグがあり、対象となるキーが無い場合は次のデータへ
			if (isset($rule_list[static::CONFIG_PREMISE])) {
				foreach ((array) $rule_list[static::CONFIG_PREMISE] as $premise_key) {
					if (!isset($data[$premise_key]) || isset($errors[$premise_key])) {
						continue 2;
					}
				}
			}

			//ストップ後処理指定があり、有効な値が設定されている場合、デフォルトとして登録する。
			$stop_after = null;
			if (isset($rule_list[static::CONFIG_STOP_AFTER]) && in_array($rule_list[static::CONFIG_STOP_AFTER], array(static::OPTION_IS_LAST, static::OPTION_RAISE_EXCEPTION), true)) {
				$stop_after = $rule_list[static::CONFIG_STOP_AFTER];
			}

			//例外対応フラグの取得
			$config_raise_exception = Arrays::AdjustValue($rule_list, static::CONFIG_RAISE_EXCEPTION, false);

			//エラー時停止フラグの取得
			$config_is_last = Arrays::AdjustValue($rule_list, static::CONFIG_IS_LAST,false);

			//値によるバリデーションセットの切り替え
			if (isset($rule_list[static::CONTIG_SET_VALIDATE_TYPE]) && is_callable($rule_list[static::CONTIG_SET_VALIDATE_TYPE])) {
				$validate_set_type = $rule_list[static::CONTIG_SET_VALIDATE_TYPE]($target_value, $rule_list);

				if ($validate_set_type === true) {
					continue;
				}

				if (!isset($rule_list[static::CONFIG_VALIDATE_SET][$validate_set_type])) {
					CoreException::RaiseSystemError('Validation設定：judgeが存在しますが、validate_setが設定されていません。');
				}

				$rule_list = $rule_list[static::CONFIG_VALIDATE_SET][$validate_set_type] + $rule_list;
			}

			//----------------------------------------------
			//オプションの初期化
			//----------------------------------------------
			//ルール共通prefixの取得
			$prefix = Arrays::AdjustValue($rule_list, static::CONFIG_PREFIX, '');

			//ルール共通safixの取得
			$safix = Arrays::AdjustValue($rule_list, static::CONFIG_SAFIX, '');

			//単語置換帖
			$message_list = array();
			foreach (Arrays::AdjustValue($rule_list, static::CONFIG_VARS, array()) as $target => $text) {
				$message_list[$target] = $text;
			}

			if ($title = Arrays::AdjustValue($rule_list, static::CONFIG_TITLE)) {
				$message_list[static::CONFIG_TITLE] = $title;
			}

			if (!isset($message_list[static::CONFIG_TITLE])) {
				$message_list[static::CONFIG_TITLE] = $data_name;
			}

			//error配列に登録する名前
			$error_form_name = Arrays::AdjustValue($rule_list, array(static::CONFIG_FORCE_ERROR, static::CONFIG_NAME), $data_name);

			//----------------------------------------------
			//実行前最終調整
			//----------------------------------------------
			//validate以外を除去しつつ、requireとnot_emptyが存在する場合、最優先になるように調整
			//常識的な実装では二つの処理に分けるべきだが、繰り返し回数の削減を優先した
			//----------------------------------------------
			//優先されるルールのリスト
			$high_priority_rule_list = array();

			//一括処理
			array_walk($rule_list, function (&$value, $key) use (&$high_priority_rule_list) {
				//----------------------------------------------
				//validate以外向けフィルタ処理
				//----------------------------------------------
				if (!is_numeric($key)) {
					$value = null;
				}

				//----------------------------------------------
				//優先対象ルール取得処理
				//----------------------------------------------
				switch ($value[0]) {
					case 'require':
						$high_priority_rule_list['require'] = $value;
						$value = null;
						break;
					case 'not_empty':
						$high_priority_rule_list['not_empty'] = $value;
						$value = null;
						break;
					case 'is_array':
						$high_priority_rule_list['is_array'] = $value;
						$value = null;
						break;
				}

				//----------------------------------------------
				//上記のフィルタにかからないものは文字通り"何もしない"
				//----------------------------------------------
			});

			//フィルタ済み値の一括消去
			$rule_list = array_filter($rule_list);

			//優先接続対象があれば先頭から順に追加
			if (!empty($high_priority_rule_list)) {
				foreach (array('not_empty', 'is_array', 'require') as $high_priority_rule_name) {
					if (isset($high_priority_rule_list[$high_priority_rule_name])) {
						array_unshift($rule_list, $high_priority_rule_list[$high_priority_rule_name]);
					}
				}
			}

			//==============================================
			//主処理
			//==============================================
			foreach ($rule_list as $rule) {
				//----------------------------------------------
				//主処理内初期化
				//----------------------------------------------
				//ルール名の切り出し
				$rule_name = $rule[0];

				//ルールオプションの切り出し
				$options = array_slice($rule, 1);

				//省略表記の設定を掬い取る
				$option_rule_length = count($options);
				for ($i = 0;$i < $option_rule_length;$i++) {
					$data_set = array_slice($options, $i, 1);
					$idx = key($data_set);
					$option_rule = current($data_set);
					if (is_int($idx) && is_string($option_rule) && isset($option_set[$option_rule])) {
						$options = array_merge(array_slice($options, 0, $i), array($option_rule => true), array_slice($options, $i + 1));
					}
				}

				//強制検証フラグの初期化
				$option_force_validate = Arrays::AdjustValue($options, static::OPTION_FORCE_VALLIDATE, $config_force_validate);

				//----------------------------------------------
				//検証
				//----------------------------------------------
				//作業用の変数に移し替え
				$work_value = $target_value;

				//キーを見る設定にされている場合はarray_keysをかける
				if (Arrays::AdjustValue($options, static::OPTION_SEE_ARRAY_KEYS, false)) {
					if (!static::Rule(static::RULE_IS_ARRAY, $work_value, $options) && !$work_value instanceof \ArrayObject) {
						throw \ickx\fw2\core\exception\CoreException::RaiseSystemError('array_keysオプションが与えられていますが値が配列ではありません。is_arrayオプション使用時はそれより前にis_arrayルールで値を検証してください。 value:%s', array($target_value));
					}

					if ($work_value instanceof \ArrayObject) {
						$work_value = array_keys($work_value->getArrayCopy());
					} else {
						$work_value = array_keys($work_value);
					}
				}

				//対象を配列と見なさない場合、更に一段深くする
				if (Arrays::AdjustValue($options, static::OPTION_NOT_DEAL_ARRAY, false)) {
					$work_value = array($work_value);
				} else {
					//ルールに突合させて検証
					if ($rule_name === static::RULE_IS_ARRAY) {
						$work_value = array($work_value);
					} else {
						if ($work_value instanceof \ArrayObject) {
							$work_value = $work_value->getArrayCopy();
						} else {
							$work_value = (array) $work_value;
						}
					}
				}

				//強制検証フラグが無効な場合の処理
				if (!$option_force_validate) {
					//ルールレベルでの空時スキップ判定時はスキップされない
					if (Arrays::AdjustValue($options, static::OPTION_EMPTY_SKIP, false) && static::Rule(static::RULE_NOT_EMPTY, $work_value)) {
					continue;
				}

					//プレミスが設定されてあり、対象となるキーがある場合はスキップ
					if (isset($options[static::OPTION_PREMISE]) && !empty($options[static::OPTION_PREMISE])) {
						foreach ((array) $options[static::OPTION_PREMISE] as $premise_key) {
							if (isset($errors[$premise_key]) || isset($before_errors[$premise_key])) {
								continue 2;
							}
						}
					}
				}

				//値が空の場合の初期化処理
				if (empty($work_value)) {
					if ($option_force_validate) {
						//ルールレベルで強制検証フラグが有効
						$work_value = array(null);
					} else if ($rule_name === static::RULE_REQUIRE) {
						//ルールレベルでrequireが設定
						$work_value = array(null);
					}
				}

				//is array modeが有効か確認
				$mode_is_array = Arrays::AdjustValue($options, static::RULE_IS_ARRAY, false);

				//ループ回数カウント
				$idx = 0;

				//メタ情報更新
				$tmp_meta = $meta;
				$tmp_meta['loop_index']	= $idx;

				$is_last = false;

				//検証の実行
				foreach ($work_value as $key => $value) {
					if (($validator_message = static::Rule($rule_name, $value, $options, $tmp_meta)) !== true) {
						//繰り返し要素用エラーメッセージの更新
						$message_list['loop_index0'] = $idx;
						$message_list['loop_index'] = $idx + 1;
						$message_list['key'] = $key;

						//
						if (is_array($validator_message)) {
							$validator_message['validator_message'] = $validator_message['validator_message'];
						} else {
							$validator_message = array('validator_message' => $validator_message);
						}

						//エラーメッセージの構築
						list($message, $message_list) = static::CreateErrorMessage($rule_name, $message_list, $validator_message, $prefix, $safix, $options, $value, $tmp_meta);

						//メッセージがまだない場合のみリストに追加
						foreach ((array) $error_form_name as $target_form_name) {
							if (!isset($error_message_list[$target_form_name][$message])) {
								$errors[$target_form_name][] = array(
									'message'	=> $message,
									'options'	=> $options,
								);
								$error_message_list[$target_form_name][$message] = true;
							}
						}

						//ルールセットにおいて例外判定がある場合は次の処理へ
						if ((Arrays::AdjustValue($options, static::OPTION_RAISE_EXCEPTION, $config_raise_exception)) || $stop_after === static::OPTION_RAISE_EXCEPTION) {
							if (is_array($value)) {
								$value = implode(', ', $value);
							}
							throw CoreException::RaiseSystemError('message:%s rule_name:%s value:%s', array($message, $rule_name, $value));
						}

						//ルールセットにおいて末尾判定がある場合は次の処理へ
						$is_last = (Arrays::AdjustValue($options, static::OPTION_IS_LAST, $config_is_last)) || $stop_after === static::OPTION_IS_LAST;
						if ($mode_is_array !== true && $is_last) {
							break 2;
						}
					}
					$idx++;
				}

				if ($is_last) {
					break;
				}
			}
		}

		//==============================================
		//結果の返却
		//==============================================
		return $errors;
	}

	/**
	 * エラーメッセージを構築します。
	 *
	 * @param	string	$rule_name			ルール名
	 * @param	array	$message_list		既存の置換用メッセージリスト
	 * @param	array	$validator_message	バリデータが返したメッセージ
	 * @param	string	$prefix				メッセージプリフィックス
	 * @param	string	$safix				メッセージサフィックス
	 * @param	array	$options			オプション
	 * @param	mixed	$value				値
	 * @return	array	エラーメッセージと更新されたメッセージリストの配列
	 */
	public static function CreateErrorMessage ($rule_name, $message_list = array(), $validator_message = array(), $prefix = '', $safix = '', $options = array(), $value = null, $meta = array()) {
		//エラーメッセージの構築
		$ret = Arrays::AdjustValue($options, 'message', static::GetErrorMessage($rule_name));
		if (is_object($ret) && is_callable($ret)) {
			$ret = $ret($value, $options, $meta);
		}

		//メッセージの構築
		$message_list += array_merge($message_list + $options + static::GetExtraReplaceValues($rule_name, $value, $options), $validator_message);

		//メッセージの差し替え
		$before_ret = '';
		while (preg_match_all("/\{:([^:]+)(?::(0|[1-9][0-9]*))?\}/u", $ret, $matches, \PREG_SET_ORDER) !== false && $before_ret !== $ret) {
			$before_ret = $ret;
			foreach ($matches as $stage) {
				if (isset($message_list[$stage[1]])) {
					$message = $message_list[$stage[1]];
				} else {
					switch ($stage[1]) {
						case 'value':
							$message = $value;
							break;
						case 'encoding':
							$message = static::DetectEncoding($value, $options);
							break;
						default:
							$tmp_array = array_slice($stage, 1);
							if (!$tmp_array) {
								$tmp_array = array();
							}
							foreach ($tmp_array as $key) {
								if (isset($options[$key]) || array_key_exists($key, $options)) {
									$message = is_null($options[$key]) ? 'NULL' : $options[$key];
									continue 2;
								}
							}
							$message = Arrays::AdjustValue($message_list, Arrays::AdjustValue($stage, 2, ''), $stage[0]);
						continue;
					}
				}

				if (is_object($message)) {
					$refObj = new \ReflectionObject($message);
					$message = $refObj->hasMethod('__toString') ? (string) $message : '';
				}
				if (is_array($message)) {
					$message = implode(', ', $message);
				}

				$ret = str_replace($stage[0], $message, $ret);
			}
		}

		//値の返却
		return array($prefix . $ret . $safix, $message_list);
	}

	/**
	 * 拡張差し替え値リストを構築します。
	 *
	 * @param	string	$rule_name		ルール名
	 * @param	mixed	$value			値
	 * @param	array	$options		オプション
	 * @return	array	拡張差し替え値の配列
	 */
	public static function GetExtraReplaceValues ($rule_name, $value, array $options) {
		$rule_set = static::GetValidateRuleList();
		$rule_set = $rule_set[$rule_name];
		if (!isset($rule_set[2])) {
			return array();
		}

		$rule_set = $rule_set[2];
		if (!is_array($rule_set)) {
			return array();
		}
		foreach ($rule_set as $rule_name => $replacement) {
			$rule_set[$rule_name] = (is_callable($replacement)) ? $replacement($value, $options) : $value;
		}
		return $rule_set;
	}

	//==============================================
	//Valid setting
	//==============================================
	/**
	 * バリデートルールのリストを返します。
	 *
	 * @param	array	バリデートルールのリスト
	 */
	public static function GetValidateRuleList () {
		return static::LasyClassVarAccessCallback(
			'_rule',
			function () {return static::DefaultRule();}
		);
	}

	/**
	 * ルールの追加
	 *
	 * @param	string	$rule_name	ルール名
	 * @param	array	$rule		ルール
	 */
	public static function AppendRule ($rule_name, $rule) {
		$rule_list = static::GetValidateRuleList();
		$rule_list[$rule_name] = $rule;
		static::SetClassVar('_rule', $rule_list);
	}

	/**
	 * ルールのデフォルトメッセージを変更
	 *
	 * @param	string	$rule_name	ルール名
	 * @param	string	$message	変更するデフォルトメッセージ
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合
	 */
	public static function ReplaceRuleMessage ($rule_name, $message) {
		$rule_list = static::GetValidateRuleList();
		if (!Arrays::KeyExists($rule_list, $rule_name)) {
			throw \ickx\fw2\core\exception\CoreException::RaiseSystemError('存在しないルール名を指定されました。%s', array($rule_name));
		}
		$rule_list[$rule_name][1] = $message;
		static::SetClassVar('_rule', $rule_list);
	}

	/**
	 * ルールの除去
	 *
	 * @param	string	$rule_name	ルール名
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合
	 */
	public static function RemoveRule ($rule_name) {
		$rule_list = static::GetValidateRuleList();
		if ($rule_list->$rule_name === null) {
			throw \ickx\fw2\core\exception\CoreException::RaiseSystemError('存在しないルール名を指定されました。%s', array($rule_name));
		}
		unset($rule_list[$rule_name]);
		static::SetClassVar('_rule', $rule_list);
	}

	//==============================================
	//Valid method
	//==============================================
	/**
	 * callback rule時の処理
	 *
	 * @param	string	$value		検証する値
	 * @param	array	$options	オプション
	 * @param	array	$meta		メタ情報
	 * @return	bool	検証に合格した場合:true、検証に失敗した場合:false
	 * @throws	\ickx\fw2\core\exception\CoreException	検証ルールが実在しなかった場合や検証メソッドが存在しない場合、返り値がboolでない場合
	 */
	public static function Callback ($value, $options, $meta = array()) {
		//==============================================
		//起動検証と初期化
		//==============================================
		//ターゲット関数の取得
		$function_name = Arrays::AdjustValue($options, 0);
		$function_name = $function_name ?: Arrays::AdjustValue($options, 'function');

		//引数の取得
		$args = Arrays::AdjustValue($options, 'args', array());

		//呼び出し可能か検証
		if (!is_callable($function_name, false, $callable_name)) {
			throw \ickx\fw2\core\exception\CoreException::RaiseSystemError('メソッドが実在しないか、コールバックできない関数を指定されました。%s', array($callable_name));
		}

		//==============================================
		//実行
		//==============================================
		$ret = $function_name($value, $args, $options, $meta);

		//返り値はboolのみ許可
		if (!is_bool($ret)) {
			throw \ickx\fw2\core\exception\CoreException::RaiseSystemError('返り値がboolでない：%s', array($ret));
		}

		//==============================================
		//処理の終了
		//==============================================
		return $ret;
	}

	//==============================================
	//Utility
	//==============================================
	public static function GetOptionSet () {
		return static::LasyClassVarAccessCallback(
			'_options',
			function () {return array(
				static::OPTION_RAISE_EXCEPTION	=> static::OPTION_RAISE_EXCEPTION,
				static::OPTION_IS_LAST			=> static::OPTION_IS_LAST,
				static::OPTION_NOT_DEAL_ARRAY	=> static::OPTION_NOT_DEAL_ARRAY,
				static::OPTION_EMPTY_SKIP		=> static::OPTION_EMPTY_SKIP,
				static::OPTION_SEE_ARRAY_KEYS	=> static::OPTION_SEE_ARRAY_KEYS,
				static::OPTION_FORCE_VALLIDATE	=> static::OPTION_FORCE_VALLIDATE,
			);}
		);
	}

	public static function AdjustUploadFile ($data, $data_name) {
		$multiple = is_array(Arrays::AdjustValue(Arrays::AdjustValue($data, 'name', array()), $data_name));

		$files = array();
		if ($multiple) {
			foreach (static::filesKeyList() as $key) {
				foreach ($data[$key] as $values) {
					foreach ($values as $idx => $value) {
						$files[$idx][$key] = $value;
					}
				}
			}
		} else {
			foreach (static::filesKeyList() as $key) {
				$files[0][$key] = $data[$key];
			}
		}

		foreach ($files as $idx => $file) {
			if (!isset($file['error']) || !is_int($file['error'])) {
				$files[0] = null;
			}
		}

		return $multiple ? (empty($files) ? null : $files) : Arrays::AdjustValue($files, 0);
	}

	/**
	 * error時用メッセージを返します。
	 *
	 * @param	string	$rule_name	検証ルール名
	 * @return	string	error時用メッセージ
	 */
	public static function GetErrorMessage ($rule_name) {
		$rule = static::GetValidateRuleList();
		return $rule[$rule_name][1];
	}

	//==============================================
	//For utility const
	//==============================================
	public static function filesKeyList () {
		return array(
			'name',
			'type',
			'size',
			'tmp_name',
			'error',
		);
	}

	//==============================================
	// ClassVariableTrait
	//==============================================
	/** @staticvar	array	共有変数リスト */
	protected static $_ClassVariableTrait_Data = array();

	/** @staticvar	array	定数化設定リスト */
	protected static $_ClassVariableTrait_ConstList = array();

	/**
	 * コールバック関数を用いて上書き禁止設定のクラス変数を設定します。
	 *
	 * 特性上、クラス変数が削除されない限り、コールバック関数は一度しか呼ばれません。
	 *
	 * @param	string		$name		クラス変数名
	 * @param	callable	$call_back	値を出力するコールバック関数
	 * @return	mixed		設定した値
	 */
	public static function LasyClassVarConstAccessCallback ($name, $call_back) {
		if (!isset(static::$_ClassVariableTrait_Data[$name])) {
			static::$_ClassVariableTrait_Data[$name] = $call_back();
			static::$_ClassVariableTrait_ConstList[implode('=>', Arrays::AdjustArray($name))] = true;
		}
		return static::$_ClassVariableTrait_Data[$name];
	}

	/**
	 * コールバック関数を用いてクラス変数を設定します。
	 *
	 * 特性上、クラス変数が削除されない限り、コールバック関数は一度しか呼ばれません。
	 *
	 * @param	string		$name		クラス変数名
	 * @param	callable	$call_back	値を出力するコールバック関数
	 * @return	mixed		設定した値
	 */
	public static function LasyClassVarAccessCallback ($name, $call_back) {
		if (!isset(static::$_ClassVariableTrait_Data[$name])) {
			static::$_ClassVariableTrait_Data[$name] = $call_back();
			static::$_ClassVariableTrait_ConstList[implode('=>', Arrays::AdjustArray($name))] = false;
		}
		return static::$_ClassVariableTrait_Data[$name];
	}

	/**
	 * 上書き禁止設定のクラス変数を設定します。
	 *
	 * @param	string	$name		クラス変数名
	 * @param	mixed	$value		クラス変数値
	 */
	public static function SetClassVarConst ($name, $value) {
		static::SetClassVar($name, $value, true);
	}

	/**
	 * クラス変数を設定します。
	 *
	 * @param	string	$name		クラス変数名
	 * @param	mixed	$value		クラス変数値
	 * @param	bool	$const_flag	上書き禁止設定
	 */
	public static function SetClassVar ($name, $value, $const_flag = false) {
		$name_key = implode('=>', (array) $name);
		if ($const_flag && isset(static::$_ClassVariableTrait_ConstList[$name_key])) {
			throw CoreException::RaiseSystemError('%s is constant', array($name_key));
		}
		if (is_array($name)) {
			static::$_ClassVariableTrait_Data = Arrays::SetLowest(static::$_ClassVariableTrait_Data, $name, $value);
		} else {
			static::$_ClassVariableTrait_Data[$name] = $value;
		}

		static::$_ClassVariableTrait_ConstList[$name_key] = $const_flag;
	}

	/**
	 * クラス変数を取得します。
	 *
	 * @param	string	$name		クラス変数名
	 * @return	mixed	クラス変数値
	 */
	public static function GetClassVar ($name, $default_value = null) {
		if (is_array($name)) {
			return Arrays::GetLowest(static::$_ClassVariableTrait_Data, $name) ?: $default_value;
		}
		return isset(static::$_ClassVariableTrait_Data[$name]) ? static::$_ClassVariableTrait_Data[$name] : $default_value;
	}

	/**
	 * 全てのクラス変数を取得します。
	 *
	 * @return	array	全てのクラス変数
	 */
	public static function GetClassVarAll () {
		return static::$_ClassVariableTrait_Data;
	}

	/**
	 * クラス変数が存在するかどうか判定します。
	 *
	 * @param	string	$name		クラス変数名
	 * @return	bool	クラス変数が存在する場合はbool true, そうでない場合はfalse
	 */
	public static function HasClassVar ($name) {
		return Arrays::ExistsLowest(static::$_ClassVariableTrait_Data, $name);
	}

	/**
	 * クラス変数を削除します。
	 *
	 * @param	string	$name	クラス変数名
	 */
	public static function RemoveClassVar ($name) {
		$name = Arrays::AdjustValue($name);
		if (Arrays::AdjustValue(static::$_ClassVariableTrait_ConstList, implode('=>', Arrays::AdjustValue($name)))) {
			throw CoreException::RaiseSystemError('%s is constant', array(implode(' => ', $name)));
		}
		static::$_ClassVariableTrait_Data = Arrays::RemoveLowest(static::$_ClassVariableTrait_Data, $name);
		unset(static::$_ClassVariableTrait_ConstList[implode('=>', Arrays::AdjustValue($name))]);
	}
}
