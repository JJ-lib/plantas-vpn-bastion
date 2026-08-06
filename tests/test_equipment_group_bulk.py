import importlib.util, os, tempfile, unittest, io, re
from pathlib import Path
class EquipmentPlantNavigationTest(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();os.environ["PANEL_DB"]=str(Path(cls.tmp.name)/"panel.db")
  spec=importlib.util.spec_from_file_location("panel_grouped",os.environ.get("PANEL_APP_UNDER_TEST",str(Path(__file__).resolve().parents[1] / "panel-app/app.py")));cls.mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.mod)
  assert cls.mod.DB==os.environ["PANEL_DB"]
  cls.client=cls.mod.app.test_client()
  with cls.client.session_transaction() as sess: sess['uid']=1;sess['role']='admin';sess['username']='admin'
 @classmethod
 def tearDownClass(cls): cls.tmp.cleanup()
 def setUp(self):
  with self.mod.app.app_context():
   conn=self.mod.db()
   for table in ('equipment_tags','permissions','plant_permissions','equipment_import_batches','equipment','vpns'):
    conn.execute('DELETE FROM '+table)
   conn.execute("INSERT INTO equipment(id,plant,name,kind,real_ip,real_port,active,created_at,web_mode,web_effective_mode) VALUES(?,?,?,?,?,?,?,?,?,?)",(1,'Example Site North','Inversor 1','WEB','192.0.2.3','80',1,'now','direct','direct'))
   conn.execute("INSERT INTO vpns(id,plant,slug,host,port,username,password_enc,active,created_at,vpn_type) VALUES(?,?,?,?,?,?,?,?,?,?)",(1,'Example Site North','example-site-north','vpn.example.test','443','synthetic-user','',1,'now','ssl'))
   conn.commit()
 def test_plant_cards_collapse_whitespace_and_case_variants(self):
  with self.mod.app.app_context():
   self.mod.db().execute("insert into vpns(plant,slug,host,port,username,password_enc,active,created_at) values(?,?,?,?,?,?,?,?)",('Example Site 01 ','example-site-01','vpn.test','443','u','',1,'now'))
   self.mod.db().execute("insert into equipment(plant,name,kind,real_ip,real_port,active,created_at,web_mode,web_effective_mode) values(?,?,?,?,?,?,?,?,?)",('example   site 01','Example Site Equipment','WEB','192.0.2.1','80',1,'now','direct','direct'));self.mod.db().commit()
  root=self.client.get('/admin/equipment');body=root.get_data(as_text=True)
  self.assertEqual(200,root.status_code);self.assertEqual(1,body.count('/admin/equipment/plant/Example%20Site%2001'))
  scoped=self.client.get('/admin/equipment/plant/Example%20Site%2001');self.assertEqual(200,scoped.status_code);self.assertIn('Example Site Equipment',scoped.get_data(as_text=True))
  with self.mod.app.app_context():
   self.mod.normalize_plant_data(self.mod.db());self.mod.db().commit();self.assertEqual(['Example Site 01'],[r[0] for r in self.mod.db().execute("select distinct plant from vpns where slug='example-site-01' union select distinct plant from equipment where name='Example Site Equipment'")]);self.assertIsNotNone(self.mod.vpn_for_plant('Example Site 01'))
 def test_vpn_save_rejects_logically_duplicate_plant_name(self):
  with self.mod.app.app_context():
   self.mod.db().execute("insert into vpns(plant,slug,host,port,username,password_enc,active,created_at,vpn_type) values(?,?,?,?,?,?,?,?,?)",('Example Site 01','example-site-01','vpn.example.test','443','synthetic-user','',1,'now','ssl'))
   self.mod.db().commit()
   row=dict(self.mod.db().execute("select * from vpns where slug='example-site-north'").fetchone());vals={k:row.get(k) for k in self.mod.WRITE};vals.update(plant='  example   site 01  ',slug='example-site-01')
   with self.assertRaisesRegex(ValueError,'(?i)ya existe'): self.mod.save_vpn(vals)
 def test_admin_equipment_navigates_from_plants_to_their_equipment(self):
  root=self.client.get('/admin/equipment');self.assertEqual(200,root.status_code);html=root.get_data(as_text=True)
  self.assertIn('Example Site North',html);self.assertIn('/admin/equipment/plant/Example%20Site%20North',html);self.assertNotIn('192.0.2.3:80',html)
  scoped=self.client.get('/admin/equipment/plant/Example%20Site%20North');self.assertEqual(200,scoped.status_code);detail=scoped.get_data(as_text=True)
  self.assertIn('Inversor 1',detail);self.assertIn('192.0.2.3:80',detail);self.assertIn('/admin/equipment/new?plant=Example%20Site%20North',detail)
 def test_new_equipment_is_locked_to_selected_plant(self):
  response=self.client.get('/admin/equipment/new?plant=Example%20Site%20North');self.assertEqual(200,response.status_code);html=response.get_data(as_text=True)
  self.assertIn("<input type='hidden' name='plant' value='Example Site North'>",html);self.assertNotIn("<select name='plant'",html)
 def test_manual_equipment_post_resolves_plant_to_canonical_name(self):
  original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:[]
  try:
   response=self.client.post('/admin/equipment/new',data={'plant':'Example Site North','name':'Canónico','kind':'WEB','real_ip':'192.0.2.1','real_port':'80','path':'/','public_port':'9751','web_mode':'direct','description':''});self.assertEqual(302,response.status_code)
   with self.mod.app.app_context():self.assertEqual('Example Site North',self.mod.db().execute("select plant from equipment where name='Canónico'").fetchone()[0])
  finally:self.mod.publish_plant=original
 def test_bulk_csv_parses_per_equipment_web_modes_and_allocates_ports(self):
  raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\n"
       "Directo;WEB;192.0.2.10;80;/;;direct;sin proxy\n"
       "Compatible;WEB;192.0.2.11;8080;/login;;rewrite_cache;reescribir\n").encode()
  rows=self.mod.parse_bulk_csv(raw,'Example Site North',used_ports={8081})
  self.assertEqual(['direct','rewrite_cache'],[r['web_mode'] for r in rows]);self.assertEqual('Example Site North',rows[0]['plant'])
  self.assertEqual(2,len({r['proxy_port'] for r in rows}));self.assertNotIn(8081,{r['proxy_port'] for r in rows})
 def test_bulk_import_screen_and_template_expose_web_mode(self):
  screen=self.client.get('/admin/equipment/plant/Example%20Site%20North/import');self.assertEqual(200,screen.status_code);body=screen.get_data(as_text=True)
  self.assertIn('Importar equipos',body);self.assertIn('auto, direct, rewrite_cache',body);self.assertIn('/admin/equipment/import/template.csv',body)
  template=self.client.get('/admin/equipment/import/template.csv');self.assertEqual(200,template.status_code);text=template.get_data(as_text=True)
  self.assertIn('modo_web',text);self.assertIn('rewrite_cache',text)
 def test_bulk_import_asks_before_changing_an_existing_ip(self):
  original_publish=self.mod.publish_plant;calls=[];self.mod.publish_plant=lambda plant:calls.append(plant)
  try:
   raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nCSV nuevo;WEB;192.0.2.3;8080;/nuevo;;direct;reemplazo\n").encode()
   response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data');body=response.get_data(as_text=True)
   self.assertEqual(409,response.status_code);self.assertIn('IP ya existente',body);self.assertIn('192.0.2.3',body);self.assertIn('Sobrescribir',body);self.assertIn('Mantener originales',body);self.assertEqual([],calls)
   with self.mod.app.app_context():
    self.assertEqual(1,self.mod.db().execute("select count(*) from equipment where plant='Example Site North' and real_ip='192.0.2.3'").fetchone()[0]);self.assertEqual(1,self.mod.db().execute('select count(*) from equipment_import_batches').fetchone()[0])
  finally: self.mod.publish_plant=original_publish
 def test_bulk_import_saves_all_modes_and_publishes_once(self):
  original_probe=self.mod.probe_web_equipment;original_publish=self.mod.publish_plant;published=[]
  self.mod.probe_web_equipment=lambda slug,ip,port,mode:{'effective_mode':('rewrite_cache' if mode=='rewrite_cache' else 'direct'),'diagnostic':'test '+mode}
  def publish(plant):
   published.append((plant,self.mod.db().execute('select count(*) from equipment where plant=?',(plant,)).fetchone()[0]));return [9101,9102]
  self.mod.publish_plant=publish
  try:
   raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nA;WEB;192.0.2.1;80;/;9101;direct;uno\nB;WEB;192.0.2.2;80;/;9102;rewrite_cache;dos\n").encode()
   response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data')
   self.assertEqual(302,response.status_code);self.assertIn('/admin/equipment/plant/Example%20Site%20North',response.headers['Location'])
   with self.mod.app.app_context(): rows=self.mod.db().execute("select name,web_mode,web_effective_mode,web_proxy_port from equipment where plant=? and name in ('A','B') order by name",('Example Site North',)).fetchall()
   self.assertEqual([('A','direct','direct'),('B','rewrite_cache','rewrite_cache')],[(r['name'],r['web_mode'],r['web_effective_mode']) for r in rows]);self.assertIsNotNone(rows[1]['web_proxy_port']);self.assertEqual(1,len(published));self.assertEqual('Example Site North',published[0][0])
  finally: self.mod.probe_web_equipment=original_probe;self.mod.publish_plant=original_publish
 def test_bulk_import_keep_preserves_duplicates_and_adds_only_new_ips(self):
  original_probe=self.mod.probe_web_equipment;original_publish=self.mod.publish_plant;published=[]
  self.mod.probe_web_equipment=lambda slug,ip,port,mode:{'effective_mode':'direct','diagnostic':'test'};self.mod.publish_plant=lambda plant:published.append(plant) or [9501]
  try:
   raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nNo cambiar;WEB;192.0.2.3;8080;/nuevo;;direct;duplicado\nSolo nuevo;WEB;192.0.2.1;80;/;9501;direct;nuevo\n").encode()
   first=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data');token=re.search("name=batch_token value='([^']+)'",first.get_data(as_text=True)).group(1)
   response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'batch_token':token,'duplicate_policy':'keep'})
   self.assertEqual(302,response.status_code);self.assertEqual(['Example Site North'],published)
   with self.mod.app.app_context():
    old=self.mod.db().execute("select name,real_port from equipment where plant='Example Site North' and real_ip='192.0.2.3'").fetchone();self.assertEqual(('Inversor 1','80'),tuple(old));self.assertEqual(1,self.mod.db().execute("select count(*) from equipment where plant='Example Site North' and real_ip='192.0.2.1'").fetchone()[0]);self.assertEqual(0,self.mod.db().execute('select count(*) from equipment_import_batches where token=?',(token,)).fetchone()[0])
  finally:self.mod.probe_web_equipment=original_probe;self.mod.publish_plant=original_publish
 def test_bulk_import_overwrite_updates_in_place_and_preserves_port_and_permissions(self):
  with self.mod.app.app_context():
   cur=self.mod.db().execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port,web_mode,web_effective_mode) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",('Example Site North','Original','WEB','192.0.2.1','80','/','http://203.0.113.179:9600/','original',1,'now',9600,'direct','direct'));eid=cur.lastrowid;self.mod.db().execute('insert or ignore into permissions(user_id,equipment_id) values(?,?)',(1,eid));self.mod.db().commit()
  original_probe=self.mod.probe_web_equipment;original_publish=self.mod.publish_plant;published=[]
  self.mod.probe_web_equipment=lambda slug,ip,port,mode:{'effective_mode':'rewrite_cache','diagnostic':'test overwrite'};self.mod.publish_plant=lambda plant:published.append(plant) or [9600]
  try:
   raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nSobrescrito;WEB;192.0.2.1;8088;/nuevo;;rewrite_cache;actualizado\n").encode();first=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data');token=re.search("name=batch_token value='([^']+)'",first.get_data(as_text=True)).group(1)
   response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'batch_token':token,'duplicate_policy':'overwrite'});self.assertEqual(302,response.status_code);self.assertEqual(['Example Site North'],published)
   with self.mod.app.app_context():
    rows=self.mod.db().execute("select * from equipment where plant='Example Site North' and real_ip='192.0.2.1'").fetchall();self.assertEqual(1,len(rows));row=rows[0];self.assertEqual(eid,row['id']);self.assertEqual(('Sobrescrito','8088',9600,'rewrite_cache'),(row['name'],row['real_port'],row['proxy_port'],row['web_effective_mode']));self.assertEqual(1,self.mod.db().execute('select count(*) from permissions where user_id=1 and equipment_id=?',(eid,)).fetchone()[0])
  finally:self.mod.probe_web_equipment=original_probe;self.mod.publish_plant=original_publish
 def test_bulk_import_rejects_same_ip_twice_inside_csv(self):
  raw=("nombre;tipo;ip;puerto;modo_web\nUno;WEB;192.0.2.1;80;direct\nDos;WEB;192.0.2.1;8080;direct\n").encode();response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'duplicado.csv')},content_type='multipart/form-data');self.assertEqual(400,response.status_code);self.assertIn('repetida dentro del CSV',response.get_data(as_text=True))
  with self.mod.app.app_context():self.assertEqual(0,self.mod.db().execute("select count(*) from equipment where real_ip='192.0.2.1'").fetchone()[0])
 def test_bulk_import_same_ip_in_another_plant_is_not_a_duplicate(self):
  with self.mod.app.app_context():self.mod.db().execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,?,?,?)",('Other Example Site','Solapado','WEB','192.0.2.1','80','/','http://x:9700/','',1,'now',9700));self.mod.db().commit()
  original=self.mod.publish_plant;calls=[];self.mod.publish_plant=lambda plant:calls.append(plant) or [9701]
  try:
   raw=("nombre;tipo;ip;puerto;puerto_publico;modo_web\nPermitido;WEB;192.0.2.1;80;9701;direct\n").encode();response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'solapado.csv')},content_type='multipart/form-data');self.assertEqual(302,response.status_code);self.assertEqual(['Example Site North'],calls)
  finally:self.mod.publish_plant=original
 def test_bulk_overwrite_rolls_back_if_publication_fails(self):
  with self.mod.app.app_context():
   cur=self.mod.db().execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port,web_mode,web_effective_mode) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",('Example Site North','Antes','WEB','192.0.2.1','80','/','http://x:9650/','antes',1,'now',9650,'direct','direct'));eid=cur.lastrowid;self.mod.db().execute('insert or ignore into permissions(user_id,equipment_id) values(1,?)',(eid,));self.mod.db().commit()
  original=self.mod.publish_plant;self.mod.publish_plant=lambda plant:(_ for _ in ()).throw(RuntimeError('fallo publicación'))
  try:
   raw=("nombre;tipo;ip;puerto;modo_web\nDespués;WEB;192.0.2.1;8080;direct\n").encode();first=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'rollback.csv')},content_type='multipart/form-data');token=re.search("name=batch_token value='([^']+)'",first.get_data(as_text=True)).group(1);response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'batch_token':token,'duplicate_policy':'overwrite'});self.assertEqual(500,response.status_code)
   with self.mod.app.app_context():
    rows=self.mod.db().execute("select id,name,real_port,proxy_port from equipment where plant='Example Site North' and real_ip='192.0.2.1'").fetchall();self.assertEqual([(eid,'Antes','80',9650)],[tuple(r) for r in rows]);self.assertEqual(1,self.mod.db().execute('select count(*) from permissions where user_id=1 and equipment_id=?',(eid,)).fetchone()[0])
  finally:self.mod.publish_plant=original
 def test_bulk_import_rejects_whole_file_when_one_row_is_invalid(self):
  raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nValido;WEB;192.0.2.1;80;/;9201;direct;uno\nInvalido;WEB;192.0.2.2;80;/;9202;modo_inventado;dos\n").encode()
  with self.mod.app.app_context(): before=self.mod.db().execute("select count(*) from equipment where plant=?",('Example Site North',)).fetchone()[0]
  response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data');self.assertEqual(400,response.status_code)
  with self.mod.app.app_context(): after=self.mod.db().execute("select count(*) from equipment where plant=?",('Example Site North',)).fetchone()[0]
  self.assertEqual(before,after)
 def test_bulk_import_rolls_back_database_when_publication_fails(self):
  original_probe=self.mod.probe_web_equipment;original_publish=self.mod.publish_plant;calls=[]
  self.mod.probe_web_equipment=lambda slug,ip,port,mode:{'effective_mode':'direct','diagnostic':'test'}
  def fail(plant): calls.append(plant);raise RuntimeError('fallo simulado')
  self.mod.publish_plant=fail
  try:
   raw=("nombre;tipo;ip;puerto;ruta;puerto_publico;modo_web;descripcion\nRollback;WEB;192.0.2.1;80;/;9301;direct;uno\n").encode()
   response=self.client.post('/admin/equipment/plant/Example%20Site%20North/import',data={'csv_file':(io.BytesIO(raw),'equipos.csv')},content_type='multipart/form-data');self.assertEqual(500,response.status_code)
   with self.mod.app.app_context(): count=self.mod.db().execute("select count(*) from equipment where name='Rollback'").fetchone()[0]
   self.assertEqual(0,count);self.assertEqual(2,len(calls))
  finally: self.mod.probe_web_equipment=original_probe;self.mod.publish_plant=original_publish
 def test_edit_returns_to_the_same_plant(self):
  with self.mod.app.app_context(): eid=self.mod.db().execute("select id from equipment where name='Inversor 1'").fetchone()[0]
  original_probe=self.mod.probe_web_equipment;original_publish=self.mod.publish_plant
  self.mod.probe_web_equipment=lambda slug,ip,port,mode:{'effective_mode':'direct','diagnostic':'test'};self.mod.publish_plant=lambda plant:[]
  try:
   response=self.client.post(f'/admin/equipment/{eid}/edit',data={'plant':'Example Site North','name':'Inversor 1','kind':'WEB','real_ip':'192.0.2.3','real_port':'80','path':'/','public_port':'9401','web_mode':'direct','description':''})
   self.assertEqual('/admin/equipment/plant/Example%20Site%20North',response.headers['Location'])
  finally: self.mod.probe_web_equipment=original_probe;self.mod.publish_plant=original_publish
if __name__=='__main__': unittest.main()
