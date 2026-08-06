import importlib.util, os, tempfile, unittest
from pathlib import Path

class AccessPanelRedesignTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();os.environ['PANEL_DB']=str(Path(cls.tmp.name)/'panel.db')
        spec=importlib.util.spec_from_file_location('panel_redesign',os.environ.get('PANEL_APP_UNDER_TEST',(os.environ.get('PANEL_APP_UNDER_TEST','/app/app.py') if Path(os.environ.get('PANEL_APP_UNDER_TEST','/app/app.py')).exists() else str(Path(__file__).resolve().parents[1] / "panel-app/app.py"))));cls.mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.mod)
        cls.client=cls.mod.app.test_client()
        with cls.mod.app.app_context():
            db=cls.mod.db();db.execute("insert into users(username,password_hash,role,active,created_at) values('viewer','x','user',1,'now')");cls.viewer_id=db.execute("select id from users where username='viewer'").fetchone()[0]
            for plant,slug in [('Example Site North','example-site-north'),('Example Site South','example-site-south')]:db.execute("insert into vpns(plant,slug,host,port,username,password_enc,active,created_at) values(?,?,?,?,?,?,1,'now')",(plant,slug,'vpn.test','443','u',''))
            cur=db.execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,1,'now',?)",('Example Site North','Zeta SCADA','RDP','192.0.2.20','3389','','','Puesto de operación',8020));cls.rdp_id=cur.lastrowid;db.execute('insert into permissions(user_id,equipment_id) values(?,?)',(cls.viewer_id,cls.rdp_id))
            cur=db.execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,1,'now',?)",('Example Site North','Alpha WEB','WEB','192.0.2.10','80','/','http://example.test:8010/','Inversor',8010));db.execute('insert into permissions(user_id,equipment_id) values(?,?)',(cls.viewer_id,cur.lastrowid))
            db.execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,1,'now',?)",('Example Site South','Oculto','WEB','192.0.2.10','80','/','http://example.test:8011/','No autorizado',8011));db.commit()
        cls.original_runtime=cls.mod.vpn_runtime;cls.mod.vpn_runtime=lambda vpn:((True,'192.0.2.2','') if vpn['slug']=='example-site-north' else (False,'','sin túnel'))
    @classmethod
    def tearDownClass(cls):cls.mod.vpn_runtime=cls.original_runtime;cls.tmp.cleanup()
    def login_as(self,uid):
        with self.client.session_transaction() as sess:sess['uid']=uid
    def test_root_renders_plant_cards_with_live_vpn_status_instead_of_equipment(self):
        self.login_as(1);response=self.client.get('/');body=response.get_data(as_text=True);self.assertEqual(200,response.status_code)
        self.assertIn('/plant/Example%20Site%20North',body);self.assertIn('/plant/Example%20Site%20South',body);self.assertIn("data-vpn-status='online'",body);self.assertIn("data-vpn-status='offline'",body);self.assertIn('VPN online',body);self.assertIn('VPN offline',body);self.assertNotIn('192.0.2.10:80',body);self.assertNotIn('Zeta SCADA',body)
    def test_plant_detail_lists_real_endpoints_and_exposes_sortable_columns(self):
        self.login_as(1);response=self.client.get('/plant/Example%20Site%20North');body=response.get_data(as_text=True);self.assertEqual(200,response.status_code)
        self.assertIn('Alpha WEB',body);self.assertIn('Zeta SCADA',body);self.assertIn('192.0.2.10',body);self.assertIn('3389',body)
        for key in ('name','kind','ip','port','description'):self.assertIn("data-sort-key='%s'"%key,body)
        self.assertIn('function sortEquipmentTable',body);self.assertIn("data-sort-value='alpha web'",body.lower())
    def test_regular_user_only_sees_and_opens_permitted_plants(self):
        self.login_as(self.viewer_id);root=self.client.get('/').get_data(as_text=True);self.assertIn('Example Site North',root);self.assertNotIn('Example Site South',root);self.assertEqual(404,self.client.get('/plant/Example%20Site%20South').status_code)
        allowed=self.client.get('/plant/Example%20Site%20North').get_data(as_text=True);self.assertIn('Alpha WEB',allowed);self.assertIn('Zeta SCADA',allowed);self.assertNotIn('Oculto',allowed)
    def test_rdp_launch_includes_every_authorized_rdp_and_no_unauthorized_rdp(self):
        with self.mod.app.app_context():
            db=self.mod.db()
            cur=db.execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,1,'now',?)",('Example Site North','Segundo RDP','RDP','192.0.2.21','3389','','','Segundo puesto',8021)); second_id=cur.lastrowid
            db.execute('insert into permissions(user_id,equipment_id) values(?,?)',(self.viewer_id,second_id))
            cur=db.execute("insert into equipment(plant,name,kind,real_ip,real_port,path,public_url,description,active,created_at,proxy_port) values(?,?,?,?,?,?,?,?,1,'now',?)",('Example Site South','RDP no autorizado','RDP','192.0.2.21','3389','','','Oculto',8022)); hidden_id=cur.lastrowid; db.commit()
        captured={}; original=self.mod.guacamole_token
        def capture(username,launches,now_ms=None): captured['username']=username;captured['launches']=launches;return 'opaque'
        self.mod.guacamole_token=capture
        try:
            self.login_as(self.viewer_id); response=self.client.get(f'/equipment/{self.rdp_id}/rdp')
        finally:
            self.mod.guacamole_token=original
            with self.mod.app.app_context():
                db=self.mod.db(); db.execute('delete from permissions where equipment_id=?',(second_id,)); db.execute('delete from equipment where id in (?,?)',(second_id,hidden_id)); db.commit()
        self.assertEqual(302,response.status_code)
        names={e['name'] for e,slug in captured['launches']}
        self.assertEqual({'Zeta SCADA','Segundo RDP'},names)
        self.assertNotIn('force-json-auth',response.headers['Location'])

    def test_plant_detail_has_styled_back_button_next_to_breadcrumb(self):
        self.login_as(1);body=self.client.get('/plant/Example%20Site%20North').get_data(as_text=True)
        self.assertIn("class='breadcrumb-row'",body)
        self.assertIn("class='btn outline back-button' href='/' aria-label='Volver al panel'",body)
        self.assertIn('← Atrás',body)
    def test_online_vpn_status_uses_success_green(self):
        self.login_as(1);body=self.client.get('/').get_data(as_text=True)
        self.assertIn('--success:#16a34a',body)
        self.assertIn(".status[data-vpn-status='online']",body)
        self.assertIn("data-vpn-status='online'",body)
    def test_singular_equipment_labels_are_grammatical(self):
        self.login_as(1);root=self.client.get('/').get_data(as_text=True);detail=self.client.get('/plant/Example%20Site%20South').get_data(as_text=True)
        self.assertIn("plant-count'>1</div><p class='plant-meta'>equipo disponible",root);self.assertNotIn("plant-count'>1</div><p class='plant-meta'>equipos disponibles",root);self.assertIn('1 equipo</span>',detail)
    def test_layout_has_persistent_light_dark_theme_toggle_and_reference_tokens(self):
        self.login_as(1);body=self.client.get('/').get_data(as_text=True);self.assertIn("id='theme-toggle'",body);self.assertIn("localStorage.getItem('theme')",body);self.assertIn("localStorage.setItem('theme'",body);self.assertIn("[data-theme='dark']",body);compact=body.replace(' ','');self.assertIn('--card-radius:24px',compact);self.assertIn('--control-radius:18px',compact)
if __name__=='__main__':unittest.main()
