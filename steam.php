#!/usr/bin/env php
<?php
set_time_limit( 0 );

include_once  __DIR__ . '/Crypt/RSA.php';

$bots = glob( __DIR__ . '/config/*.json', GLOB_BRACE );
usort(  $bots,   function($a,$b) {	return basename($a) <=> basename($b); } );

$counter = 0;
$bots_total = count( $bots );

$QueryTime = ExecuteRequest( 'http://api.steampowered.com/ITwoFactorService/QueryTime/v0001', array( 'steamid' => 0 ), [] );
$QueryTime = json_decode( $QueryTime, true );

$time = time();
if( isset( $QueryTime['response']['server_time'] ) )
{
	Msg( '{background-blue}Aligning Steam time.' );
	$GetTimeDifference = time( ) - $QueryTime['response']['server_time'];
}

foreach( $bots as $json )
{
	$counter++;
	
	$c = '';
	unset($c);
	
	$cookie = '';
	unset($cookie);
	
	if ($counter % 101 == 0)
	{
		for( $sleep=150; $sleep>0; $sleep-=15 )
		{
			Msg( '{background-blue}sleep '.$sleep.' seconds...' );
			sleep(15);
		}
	}
	
	$maFile = str_replace('.json', '.maFile', $json);
	$db = str_replace('.json', '.db', $json);
	$botName = basename( $json, '.json' );
	
	if( !file_exists( $maFile ) && !file_exists( $db )  )
	{
		Msg( 'maFile or db missing' );
		continue;
	}
	
	if( file_exists( $maFile ) )
	{
		$sda = json_decode( ltrim( _fread( $maFile ), chr( 239 ) . chr( 187 ) . chr( 191 ) ), true );
		$shared_secret = $sda['shared_secret'];
		$device_id = $sda['device_id'];
		$identity_secret = $sda['identity_secret'];
	}
	
	
	if( file_exists( $db ) )
	{
		$archi = json_decode( ltrim( _fread( $db ), chr( 239 ) . chr( 187 ) . chr( 191 ) ), true );
		$shared_secret = $archi['_MobileAuthenticator']['shared_secret'];
		$device_id = $archi['_MobileAuthenticator']['device_id'];
		$identity_secret = $archi['_MobileAuthenticator']['identity_secret'];
	}
	
	$asf = json_decode( ltrim( _fread( $json ), chr( 239 ) . chr( 187 ) . chr( 191 ) ), true );
	
	if( isset ( $asf['SteamLogin'], $asf['SteamPassword'], $asf['SteamUserPermissions'], $asf['SteamTradeToken'] ) )
	{
		$SteamLogin = $asf['SteamLogin'];
		$SteamPassword = $asf['SteamPassword'];
		$SteamUserPermissions = $asf['SteamUserPermissions'];
		$SteamTradeToken = $asf['SteamTradeToken'];
		
		$sendtradeID = '';
		foreach($SteamUserPermissions as $admin => $perm)
		{
			if( $perm == 3 )
			{
				$sendtradeID = $admin;
				break;
			}
		}
		
		if( empty( $sendtradeID ) )
		{
			Msg( '{lightred}' . $counter . '/' . $bots_total . ' - ' . $botName . '  Missing SteamUserPermissions...' );
			continue;
		}
	}
	else
	{
		Msg( '{lightred}' . $counter . '/' . $bots_total . ' - ' . $botName . '  Invalid json...' );
		continue;
	}
	
	$retry = 5;
	
	do
	{
		$failed = 0;
		$store_sessionid = '';
		$community_sessionid = '';
		$vanityurl = '';
		$steamid = '';
		
		$getrsakey = ExecuteRequest( 'https://store.steampowered.com/login/getrsakey/', 'username=' . $SteamLogin . '&donotcache=' . ( microtime( true ) * 1000 ) );
		$getrsakey = json_decode( $getrsakey, true );
		
		if( $getrsakey['success'] !== true || !isset( $getrsakey['success'] ) )
		{
			Msg( '{lightred}' . $counter . '/' . $bots_total . ' - ' . $botName . '  Reconnecting...' );
			$failed = 1;
		}
		
		if( $getrsakey['success'] === true )
		{
			Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Connected to Steam!' );
			
			$RSA = new Crypt_RSA();
			$RSA->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
			$n = new Math_BigInteger($getrsakey['publickey_mod'], 16);
			$e = new Math_BigInteger($getrsakey['publickey_exp'], 16);
			$key = array("modulus"=>$n,"publicExponent"=>$e);
			$RSA->loadKey($key, CRYPT_RSA_PUBLIC_FORMAT_RAW);
			$encryptedPassword = base64_encode($RSA->encrypt($SteamPassword));
			
			$sharedSecret = base64_decode( $shared_secret );
			
			$time = time( );
			if( isset( $GetTimeDifference ) )
			{
				$time = time( ) + $GetTimeDifference;
			}
			
			$timeStr = pack( 'N*', 0 ) . pack( 'N*', floor( $time / 30 ) );
			$code = hash_hmac( 'sha1', $timeStr, $sharedSecret, true );
		 
			$b = ord( $code[19] ) & 0xF;
			$codePoint = ( ord($code[$b ]) & 0x7F) << 24 | ( ord( $code[$b + 1] ) & 0xFF) << 16 | ( ord($code[$b + 2] ) & 0xFF ) << 8 | ( ord($code[$b + 3] ) & 0xFF );
			$codeTranslations = [50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89];

			$code = '';
			for ( $i = 0; $i < 5; ++$i )
			{
				$code .= chr($codeTranslations[$codePoint % count($codeTranslations)]);
				$codePoint /= count($codeTranslations);
			}
			
			$dologin = ExecuteRequest( 'https://store.steampowered.com/login/dologin/', array( 'password' => $encryptedPassword, 'username' => $SteamLogin, 'twofactorcode' => $code, 'emailauth' => '', 'loginfriendlyname' => '', 'captchagid' => '-1', 'captcha_text' => '', 'emailsteamid' => '', 'rsatimestamp' => $getrsakey['timestamp'], 'remember_login' => 'true', 'donotcache' => ( microtime( true ) * 1000 ) ) );
			$dologin = json_decode( $dologin, true );
	
			if( $dologin['success'] !== true || !isset( $dologin['success'] ) )
			{
				Msg( '{lightred}' . $counter . '/' . $bots_total . ' - ' . $botName . '  Reconnecting...' );
				$failed = 1;
			}
	
			if( $dologin['success'] === true )
			{
				Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Logging in...' );
				
				$ret = ExecuteRequest( 'https://store.steampowered.com/account/', [], [], '', ''  );
				
				if( !preg_match( '/g_AccountID = 0;/', $ret, $offline ) )
				{
					if( preg_match( '/g_sessionID = "(.*?)";/', $ret, $sessionid ) )
					{
						$store_sessionid = $sessionid[1];
					}
				}
				
				$ret = ExecuteRequest( 'https://steamcommunity.com/my/edit/settings', [], [], '', ''  );
				
				if( preg_match( '/\/(id|profiles)\/(.*?)\//', $ret, $urlid ) );
				{
					if( $urlid[1] == 'id' )
					{
						$vanityurl = $urlid[2];
					}
					
					if( preg_match( '/g_steamID = "([0-9]*)";/', $ret, $steamid ) )
					{
						$steamid = $steamid[1];
						
						if( preg_match( '/g_sessionID = "(.*?)";/', $ret, $sessionid ) )
						{
							$community_sessionid = $sessionid[1];
						}
					}
				}
				
				if( empty( $community_sessionid ) || empty( $store_sessionid ) )
				{
					Msg( '{lightred}' . $counter . '/' . $bots_total . ' - ' . $botName . '  Reconnecting...' );
					$failed = 1;
				}
			}
		}
		
		$retry--;
	}
	while( $retry >= 1 && $failed === 1 && sleep( 10 ) === 0 );
	
	if( !empty( $community_sessionid ) && !empty( $store_sessionid ) )
	{
		Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Successfully logged as ' . $steamid .  ( !empty( $vanityurl ) ? '/' . $vanityurl : '' ) . '.' );
		
		$salevote = ExecuteRequest( 'https://store.steampowered.com/steamawards', [], [], '', '', false );
		
		if( preg_match( '/award_card_btn/', $salevote ) )
		{
			$datas = array();
			
			$datas[0]['url']  = 'https://store.steampowered.com/salevote';
			$datas[0]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 34, 'appid' => 814380, 'developerid' => 0 );
			$datas[0]['cookies'] = $cookie;

			$datas[1]['url']  = 'https://store.steampowered.com/salevote';
			$datas[1]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 35, 'appid' => 620980, 'developerid' => 0 );
			$datas[1]['cookies'] = $cookie;

			$datas[2]['url']  = 'https://store.steampowered.com/salevote';
			$datas[2]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 36, 'appid' => 230410, 'developerid' => 0 );
			$datas[2]['cookies'] = $cookie;

			$datas[3]['url']  = 'https://store.steampowered.com/salevote';
			$datas[3]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 37, 'appid' => 632360, 'developerid' => 0 );
			$datas[3]['cookies'] = $cookie;

			$datas[4]['url']  = 'https://store.steampowered.com/salevote';
			$datas[4]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 38, 'appid' => 736260, 'developerid' => 0 );
			$datas[4]['cookies'] = $cookie;

			$datas[5]['url']  = 'https://store.steampowered.com/salevote';
			$datas[5]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 39, 'appid' => 752590, 'developerid' => 0 );
			$datas[5]['cookies'] = $cookie;

			$datas[6]['url']  = 'https://store.steampowered.com/salevote';
			$datas[6]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 40, 'appid' => 629760, 'developerid' => 0 );
			$datas[6]['cookies'] = $cookie;

			$datas[7]['url']  = 'https://store.steampowered.com/salevote';
			$datas[7]['post'] = array( 'sessionid' => $store_sessionid, 'voteid' => 41, 'appid' => 683320, 'developerid' => 0 );
			$datas[7]['cookies'] = $cookie;
			
			$request = ExecuteRequest( $datas, [], array( 'X-Requested-With: XMLHttpRequest' ), '', '', true );
		}
		else
		{
			Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Already voted for Steam Awards');
		}
			
		for( $n = 0; $n < 4; $n++ )
		{
			$datas = array();

			$data = ExecuteRequest( 'https://store.steampowered.com/explore/', [], [], '', ''  );
			
			if( preg_match( '/Come back tomorrow/', $data ) )
			{
				if( preg_match( '/You\'ve completed your queue and have unlocked (.*?) event trading cards!/', $data, $unlocked ) )
				{
					Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Come back tomorrow! You\'ve completed your queue and have unlocked ' . $unlocked[1] . ' event trading cards!');
				}
				
				break;
			}
			
			$data = ExecuteRequest( 'https://store.steampowered.com/explore/generatenewdiscoveryqueue', array( 'sessionid' => $store_sessionid, 'queuetype' => 0 ), [], '', ''  );
			$data = json_decode( $data, true );
			
			for( $q = 0; $q < count( $data['queue'] ); $q++ )
			{
				$datas[$q]['url']  = 'https://store.steampowered.com/app/1157970/';
				$datas[$q]['post'] = array( 'appid_to_clear_from_queue' => $data['queue'][$q], 'sessionid' => $store_sessionid );
				$datas[$q]['cookies'] = $cookie;
			}
			
			$request = ExecuteRequest( $datas, [], [], '', false, true );
		}
		
		$cards = array( );
		$me_inventory = foo( $steamid, 0 );
		
		Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Checking inventory...' );
		
		$trade_me = array( );
		
		foreach( $me_inventory as $appids => $cards )
		{
			$want = array();
			
			foreach( $cards as $key => $value )
			{
				$want[$key]     = $value;
			}
			
			if( !empty( $want ) )
			{
				foreach( $want as $key => $value )
				{
					$trade_me[] = '{"appid":753,"contextid":"6","amount":1,"assetid":"'.$key.'"}';
				}
			}
		}
		
		$id32 = toUserID( $sendtradeID );
		
		if( !empty( $trade_me ) )
		{
			$retry = 10;
			$success = 0;

			while( $retry >= 0 && $success == 0 )
			{
				$tradeoffer = ExecuteRequest( 'https://steamcommunity.com/tradeoffer/new/?partner='.$id32.'&token='.$SteamTradeToken, [], [], '', '', false );
				
				if(preg_match( '/"newversion":true,"version":(.*?),"/', $tradeoffer, $version ) )
				{
					$success = 1;
					$retry = 10;

					while( $retry >= 0 && $success == 0 )
					{
						$success = 0;

						$ret = ExecuteRequest( 'https://steamcommunity.com/tradeoffer/new/send', array('sessionid'=>$community_sessionid, 'serverid'=>1, 'partner'=>$sendtradeID, 'tradeoffermessage'=>'que du sale', 'json_tradeoffer'=>'{"newversion":true,"version":'.$version[1].',"me":{"assets":['.implode(',', $trade_me).'],"currency":[],"ready":false},"them":{"assets":[],"currency":[],"ready":false}}', 'captcha'=>'', 'trade_offer_create_params'=>'{"trade_offer_access_token":"'.$SteamTradeToken.'"}'), [], '', 'bCompletedTradeOfferTutorial=true;', false, 'https://steamcommunity.com/tradeoffer/new/?partner='.$id32.'&token='.$SteamTradeToken );
						$ret = json_decode( $ret, true );
						
						if( isset( $ret['tradeofferid'] ) )
						{
							$retry = 10;
							$success = 1;
							
							Msg( '{background-blue}' . $counter . '/' . $bots_total . ' - ' . $botName . $ret['tradeofferid']. ' trade sent...' );
						
							$retry = 10;

							while( $retry >= 0 && $success == 0 )
							{
								$success = 0;
								$time = time( );
								if( isset( $GetTimeDifference ) )
								{
									$time = time( ) + $GetTimeDifference;
								}
								
								$arraytime = $time;
								$tag = 'conf';
								
								$identitySecret = base64_decode( $identity_secret );
								$array = $tag ? substr( $tag, 0, 32 ) : '';
							
								for( $i=8; $i>0; $i-- )
								{
									$array = chr( $arraytime & 0xFF ) . $array;
									$arraytime >>= 8;
								}
								
								$code = base64_encode(hash_hmac( 'sha1', $array, $identitySecret, true ) );
								
								$generateconfirmation = ExecuteRequest( 'https://steamcommunity.com/mobileconf/conf?p='.$device_id.'&a='.$steamid.'&k='.$code.'&t='.$time.'&m=android&tag='.$tag, [], array('X-Requested-With: com.valvesoftware.android.steam.community'), '', '', false, '', 'Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30' );
								
								if( preg_match( '/data-confid="(\d+)" data-key="(\d+)" data-type="(\d+)" data-creator="'.$ret['tradeofferid'].'"/', $generateconfirmation, $conf ) )
								{
									$cid = $conf[1];
									$ck = $conf[2];
									$success = 1;
								}
									
								if( $success == 0 )
								{
									Msg( '{background-blue}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Confirmation (retry)');
									sleep( 5 );
								}
								
								$retry--;
							}
						}

						if( isset( $cid ) && isset( $ck ) )
						{
							$retry = 10;
							$success = 0;

							while( $retry >= 0 && $success == 0 )
							{
								$success = 0;
								
								$time = time( );
								if( isset( $GetTimeDifference ) )
								{
									$time = time( ) + $GetTimeDifference;
								}
								
								$arraytime = $time;
								$tag = 'allow';
								
								$identitySecret = base64_decode( $identity_secret );
								$array = $tag ? substr( $tag, 0, 32 ) : '';
								
								for( $i=8; $i>0; $i-- )
								{
									$array = chr( $arraytime & 0xFF ) . $array;
									$arraytime >>= 8;
								}
								
								$code = base64_encode( hash_hmac( 'sha1', $array, $identitySecret, true ) );
								
								$allow = ExecuteRequest( 'https://steamcommunity.com/mobileconf/ajaxop?op='.$tag.'&p='.$device_id.'&a='.$steamid.'&k='.$code.'&t='.$time.'&m=android&tag='.$tag.'&cid='.$cid.'&ck='.$ck, [], array('X-Requested-With: com.valvesoftware.android.steam.community'), '', '', false, '', 'Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30' );
								$allow = json_decode( $allow );
								
								if( isset( $allow->success ) && $allow->success == 1 )
								{
									$success = 1;
									Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . $ret['tradeofferid'].' - trade confirmed...' );
								}
								
								if( $success == 0 )
								{
									Msg( '{background-blue}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Confirmation (retry)');
									sleep( 5 );
								}
								
								$retry--;
							}
						}
						if( $success == 0 )
						{
							Msg( '{background-blue}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Trade (retry)');
							sleep( 5 );
						}
						
						$retry--;
					}
				}
				
				
				if( $success == 0 )
				{
					Msg( '{background-blue}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Trade (retry)');
					sleep(5);
				}
				
				$retry--;
			}
		}
		else
		{
			Msg( '{green}' . $counter . '/' . $bots_total . ' - ' . $botName . ' Nothing to trade' );
		}
	}
	
	sleep( 10 );
}

function GetCurl( )
{
	global $c;

	if( isset( $c ) )
	{
		return $c;
	}

	$c = curl_init( );

	curl_setopt_array( $c, [
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_ENCODING       => '',
		CURLOPT_TIMEOUT        => 30,
		CURLOPT_CONNECTTIMEOUT => 10,
		CURLOPT_HEADER         => true,
		// CURLOPT_COOKIESESSION  => true,
		CURLOPT_FOLLOWLOCATION => true,
		CURLOPT_AUTOREFERER    => true,
		CURLOPT_SSL_VERIFYHOST => false,
		CURLOPT_SSL_VERIFYPEER => false,
	] );

	if ( !empty( $_SERVER[ 'LOCAL_ADDRESS' ] ) )
	{
		curl_setopt( $c, CURLOPT_INTERFACE, $_SERVER[ 'LOCAL_ADDRESS' ] );
	}

	if( defined( 'CURL_HTTP_VERSION_2_0' ) )
	{
		curl_setopt( $c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0 );
	}

	return $c;
}

function ExecuteRequest( $URL, $Data = [], $Header = [], $Port = '', $cookies = '', $multithread = false, $referer = '', $useragent = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36' )
{
	global $cookie;
	
	
	if( $multithread == false )
	{
		$c = GetCurl( );
		
		if(!empty($cookies))
		{
			$cookie .= $cookies;
		}

		curl_setopt( $c, CURLOPT_URL, $URL );
		
		$Keep_Alive = array ( 'Connection: Keep-Alive', 'Keep-Alive: timeout=300' );
		$Header = array_merge( $Keep_Alive, $Header ); 

		curl_setopt( $c, CURLOPT_HTTPHEADER, $Header );
		curl_setopt( $c, CURLOPT_COOKIE, $cookie );
		curl_setopt( $c, CURLOPT_COOKIEFILE, $cookie );
		curl_setopt( $c, CURLOPT_COOKIEJAR, $cookie );
	
		curl_setopt( $c, CURLOPT_USERAGENT, $useragent );
		
		curl_setopt($c, CURLOPT_REFERER, $referer);

		if( !empty( $Port ) )
		{
			curl_setopt( $c, CURLOPT_PORT, $Port );
		}
		else
		{
			curl_setopt( $c, CURLOPT_PORT, 0 );
		}
		
		if( !empty( $Data ) )
		{
			curl_setopt( $c, CURLOPT_POST, 1 );
			curl_setopt( $c, CURLOPT_POSTFIELDS, $Data );
		}
		else
		{
			curl_setopt( $c, CURLOPT_HTTPGET, 1 );
		}
		
		$retry = 5;
		
		do
		{
			$failed = 0;
		
			$Data = curl_exec( $c );

			$responseCode = curl_getinfo( $c, CURLINFO_HTTP_CODE );
			$HeaderSize = curl_getinfo( $c, CURLINFO_HEADER_SIZE );
			
			Msg( '{background-blue}' . $URL . ' - ' . $responseCode );
			
			$Header = substr( $Data, 0, $HeaderSize );
			$Data = substr( $Data, $HeaderSize );
			
			preg_match_all( '/^Set-Cookie:\s*([^;]*)/mi', $Header, $out );
			
			foreach( $out[1] as $item )
			{
				$cookie .= $item . ';';
			}
			
			if( curl_errno ( $c ) )
			{
				$failed = 1;
				Msg( '{lightred}' . $URL . ' failed - ' . curl_error( $c ) );
			}

			if ( $responseCode >= 400 )
			{
				$failed = 1;
				Msg( '{lightred}' . $URL . ' failed - HTTP Error: ' . $responseCode );
			}
			
			$retry--;
			usleep( 300000 );
		}
		while( $retry >= 1 && $failed === 1 && sleep( 2 ) === 0 );

		return $Data;
	}
	
	if( $multithread == true )
	{
		$Keep_Alive = array ( 'Connection: Keep-Alive', 'Keep-Alive: timeout=300' );
		$Header = array_merge( $Keep_Alive, $Header ); 
		
		$mh = curl_multi_init();
		
		foreach( $URL as $id => $d )
		{
			$curl[$id] = curl_init();
			
			curl_setopt( $curl[$id], CURLOPT_URL, $d['url'] );

			curl_setopt( $curl[$id], CURLOPT_HTTPHEADER, $Header );
			curl_setopt( $curl[$id], CURLOPT_ENCODING, '' );
			// curl_setopt( $curl[$id], CURLOPT_COOKIESESSION, false );
			curl_setopt( $curl[$id], CURLOPT_COOKIE, $d['cookies'] );
			curl_setopt( $curl[$id], CURLOPT_COOKIEFILE, $d['cookies'] );
			curl_setopt( $curl[$id], CURLOPT_COOKIEJAR, $d['cookies'] );
			curl_setopt( $curl[$id], CURLOPT_RETURNTRANSFER, true );
			curl_setopt( $curl[$id], CURLOPT_TIMEOUT, 30 );
			curl_setopt( $curl[$id], CURLOPT_CONNECTTIMEOUT, 10 );
			curl_setopt( $curl[$id], CURLOPT_HEADER, true );
			curl_setopt( $curl[$id], CURLOPT_FOLLOWLOCATION, true );
			curl_setopt( $curl[$id], CURLOPT_AUTOREFERER, false );
			curl_setopt( $curl[$id], CURLOPT_SSL_VERIFYHOST, false );
			curl_setopt( $curl[$id], CURLOPT_SSL_VERIFYPEER, false );
			
			
			curl_setopt( $curl[$id], CURLOPT_POST, 1 );
			curl_setopt( $curl[$id], CURLOPT_POSTFIELDS, $d['post'] );


			if ( !empty( $_SERVER[ 'LOCAL_ADDRESS' ] ) )
			{
				curl_setopt( $curl[$id], CURLOPT_INTERFACE, $_SERVER[ 'LOCAL_ADDRESS' ] );
			}

			if( defined( 'CURL_HTTP_VERSION_2_0' ) )
			{
				curl_setopt( $curl[$id], CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0 );
			}
			
			curl_multi_add_handle( $mh, $curl[$id] );
		}
		
		$running = null;
		
		do {
			curl_multi_exec( $mh, $running );
			usleep( 300000 );
		} while ( $running > 0 );


		
		foreach( $curl as $id => $d )
		{
			$retry = 5;
	
			do
			{
				$failed = 0;
			
				$Data[$id] = curl_multi_getcontent( $d );
				curl_multi_remove_handle( $mh, $d );
				
				$responseCode = curl_getinfo( $d, CURLINFO_HTTP_CODE );
				$HeaderSize = curl_getinfo( $d, CURLINFO_HEADER_SIZE );
				
				Msg( '{background-blue}' . $URL[$id]['url'] . ' - ' . $responseCode );
				
				$Header = substr( $Data[$id], 0, $HeaderSize );
				$Data[$id] = substr( $Data[$id], $HeaderSize );
								
				// preg_match_all( '/^Set-Cookie:\s*([^;]*)/mi', $Header, $set );
					
				// foreach( $set[1] as $item )
				// {
					// $cookie .= $item . ';';
				// }
				
				if( curl_errno ( $d ) )
				{
					$failed = 1;
					Msg( '{lightred}' . $URL[$id]['url'] . ' failed - ' . curl_error( $d ) );
				}

				if ( $responseCode >= 400 )
				{
					$failed = 1;
					Msg( '{lightred}' . $URL[$id]['url'] . ' failed - HTTP Error: ' . $responseCode );
				}
				
				$retry--;
			}
			while( $retry >= 1 && $failed === 1 && usleep( 300000 ) === 0 );
		}
		
		return $Data;

		curl_multi_close( $mh );
		
	}
}

function Msg( $Message, $EOL = PHP_EOL, $printf = [] )
{
	global $DisableColors;

	$Message = str_replace(
		[
			'{normal}',
			'{green}',
			'{yellow}',
			'{lightred}',
			'{teal}',
			'{background-blue}',
		],
		$DisableColors ? '' : [
			"\033[0m",
			"\033[0;32m",
			"\033[1;33m",
			"\033[1;31m",
			"\033[0;36m",
			"\033[37;44m",
		],
	$Message, $Count );

	if( $Count > 0 && !$DisableColors )
	{
		$Message .= "\033[0m";
	}

	$Message = '[' . date( 'H:i:s' ) . '] ' . $Message . $EOL;

	if( !empty( $printf ) )
	{
		array_unshift( $printf, $Message );
		call_user_func_array( 'printf', $printf );
	}
	else
	{
		echo $Message;
	}
}

class BodyPost
{
	public static function PartPost( $name, $val )
	{
		$body = 'Content-Disposition: form-data; name="' . $name . '"';
		$body .= "\r\n\r\n".$val."\r\n";
		
		return $body;
	}

	public static function Get( array $post, $delimiter='-------------0123456789' )
	{
		if( is_array( $post ) && !empty( $post ) )
		{
			foreach( $post as $val )
				$ret = '';
				foreach( $post as $name=>$val )
				$ret .= '--' . $delimiter. "\r\n". self::PartPost( $name, $val );
				$ret .= "--" . $delimiter . "--\r\n";
		}
		else throw new \Exception( 'Error input param!' );
		return $ret;
	}
};

function foo( $steamid, $last_assetid )
{
	global $cards, $apps, $cookie;
	
	$inventory = ExecuteRequest( 'https://steamcommunity.com/inventory/'.$steamid.'/753/6?l=english&count=5000&start_assetid='.$last_assetid, [], [], '', false, false );
	$inventory = json_decode( $inventory, true );
	
	if(isset( $inventory['descriptions'] ) )
	{
		foreach( $inventory['descriptions'] as $descriptions )
		{
			if( $descriptions['tradable'] === 1 )
			{
				foreach( $descriptions['tags'] as $tags )
				{								
					if( $tags['category'] == 'cardborder' )
					{
						foreach( $inventory['assets'] as $assets )
						{
							if( $assets['classid'] == $descriptions['classid'] )
							{
								$cards[$descriptions['market_fee_app']][$assets['assetid']] = $descriptions['classid'];
							}
						}
					}
				}
			}
		}
	}
	
	if( isset( $inventory['last_assetid'] ) )
	{
		$last_assetid = $inventory['last_assetid'];
		
		sleep(1);
		
		$cards = foo( $steamid, $last_assetid );
	}
	
	return $cards;
}

function toUserID( $id )
{
    if( preg_match( '/^STEAM_/', $id ) )
	{
        $split = explode( ':', $id );
        return $split[2] * 2 + $split[1];
    }
	elseif( preg_match( '/^765/', $id ) && strlen( $id ) > 15 )
	{
        return bcsub( $id, '76561197960265728' );
    }
	else
	{
        return $id;
    }
}

function _fread ( $file = null )
{
    if( is_readable( $file ) )
	{
        if ( !( $fh = fopen( $file, 'r' ) ) ) return false;
        $data = fread( $fh, filesize( $file ) );

        $bom = pack( 'H*','EFBBBF' );
        $data = preg_replace( '/^$bom/', '', $data );

        fclose( $fh );
        return $data;
    }
    return false;
}
