<?php

require_once __DIR__ . '/require_once.php';

use ickx\fw2\security\validators\Validator;

$data			= array(
	'id'	=> 1,
);

$data_rule_list	= array(
	'id'	=> array(
		'title'	=> 'ID',
		['int'],
		['!==', 1],
	),
);

$ret = Validator::BulkCheck($data, $data_rule_list);

var_dump($ret);

$data_rule_list	= array(
	'id'	=> array(
		'title'	=> 'ID',
		['int'],
	),
);

$ret = Validator::BulkCheck($data, $data_rule_list);

var_dump($ret);

