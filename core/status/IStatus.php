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
 * @package		core
 * @author		wakaba <wakabadou@gmail.com>
 * @copyright	2011- Wakabadou honpo (http://www.wakabadou.net/) / Project ICKX (http://www.ickx.jp/)
 * @license		http://opensource.org/licenses/MIT The MIT License MIT
 * @varsion		2.0.0
 */

namespace ickx\fw2\core\status;

/**
 * Statusインターフェース
 *
 * @category	Flywheel2
 * @package		Core
 * @author		wakaba <wakabadou@gmail.com>
 * @license		http://opensource.org/licenses/MIT The MIT License MIT
 * @varsion		2.0.0
 */
interface IStatus {
	const ID_FLYWHEEL	= 2;

	const OK			= 1;
	const NG			= 2;

	const RESERVE		= 4;
	const CANCEL		= 8;

	const FOUND			= 16;
	const NOT_FOUND		= 32;

	const LEGAL			= 64;
	const ILLEGAL		= 128;

	const INFO			= 256;
	const NOTICE		= 512;
	const ERROR			= 1024;
	const WARNING		= 2048;
	const FATAL			= 4096;
	const UNKOWN		= 8192;

	const USER			= 16384;
	const SYSTEM		= 32768;

	public function getChildren ();
	public function getCode ();
	public function getSeverity ();
	public function getId ();
	public function getMessage ();
	public function getException ();
	public function isMultiStatus ();
	public function isOK ();
	public function matches ($severity_mask);
	public function __toString();
}
