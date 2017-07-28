<?php

$path_list = array(
	'constants/web/ColorCode.php',
	'core/exception/CoreException.php',
	'core/status/IStatus.php',
	'core/status/MultiStatus.php',
	'core/status/Status.php',
	'date_time/interfaces/IDateTimeConst.php',
	'international/encoding/Encoding.php',
	'other/network/DomainUtility.php',
	'security/validators/classes/ValidateTrait.php',
	'security/validators/Validator.php',
	'text/pcre/Regex.php',
	'vartype/arrays/Arrays.php',
	'vartype/arrays/LazyArrayObject.php',
	'vartype/strings/Strings.php',
);

if (!isset($path_list)) {
	$path_list= array();
	foreach (new \RecursiveDirectoryIterator(__DIR__, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_SELF) as $directoryIterator) {
		if ($directoryIterator->isDir() && substr($directoryIterator->getFilename(), 0, 1) !== '.') {
			foreach (new \RecursiveIteratorIterator($directoryIterator->getChildren(), \RecursiveIteratorIterator::LEAVES_ONLY) as $fileInfo) {
				$path_list[] = str_replace("\\", '/', $fileInfo->getSubPathname());
			}
		}
	}
}

foreach ($path_list as $path) {
	require_once __DIR__ . '/' . $path;
}
