/*	Created By �\�C�� 2013.12.30 
 *	Refference: http://pastebin.com/i6tnB8HR
 *				http://pastebin.com/tuZ6Rhtz
 *				https://www.virustotal.com/zh-tw/documentation/public-api/
 *				http://www.xlabs.com.br/index.php/noticias/21-virustotal-java-api
 *
 * 	�`�N�ƶ�:
 * 	1.Virus total����@����time frame���A�̤j�u���\4��request�A�_�h�{���o��exception
 *  2.�p�GVirus total�����|�����R�����A�h�{���ߥXexception
 */
package virustotalexample;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

import java.io.*;
import java.nio.file.Files;
import java.util.Set;

import virustotalapi.ReportFileScan;
import virustotalapi.ReportScan;
import virustotalapi.VirusTotal;

public class VirusTotalExample {

	public static void main(String[] args) throws IOException, InterruptedException {

		boolean get_report_done=false;
		
		//SHA256
		String str_sha256 = "";
		String str_url[];//array
		
		//file name
		File input_dir = new File("D:\\malware_linux_130909\\honeypot_sample_317");//input dir(��l��Ƨ�), example:��Ƨ�D:\dir1�ݭn�]�w��"D:\\dir1"
		File output_dir = new File(input_dir.getPath() + "\\output");//output dir(excel��Ƨ�)
		File done_dir = new File(input_dir.getPath() + "\\done");//done dir(���ʫ᪺��Ƨ�)
		String input_dir_files[];//��Ƨ����Ҧ��ɮײM��
		String str_upload_fpath = "";//upload���|�ɦW
		String str_done_fpath = "";//done���|�ɦW
		String str_output_fpath;//output���|
		output_dir.mkdir();//�إ�output��Ƨ�
		done_dir.mkdir();//�إ�done��Ƨ�
		
		//file io
        FileWriter dataFile;
        BufferedWriter bw;
        
		//set Virus Total API Key
        VirusTotal VT;// = new VirusTotal("c989952f44262bc7c6206732c06b7e024cad8f60e4993bdb87f1ad074cfed65d"); 

        int count=0;//���y�����ƶq
        
        //*****************************Program start*****************************
        
        input_dir_files = input_dir.list();//���o�Ҧ��ɮײM��
        
        System.out.println("�}�l���y"+input_dir_files.length+"���ɮ�");
        for(String str_fname:input_dir_files){
        	//System.out.println(str_fname);//print�ɦW
        }
        
        //1. loop scan all file
        Set <ReportFileScan> Report;
        Set <ReportScan> Report2 = null;
        
        for(String str_fname:input_dir_files){
        	
        	count+=1;
        	str_upload_fpath = input_dir.getPath() + "\\" + str_fname;
        	str_done_fpath = done_dir.getPath() + "\\" + str_fname;
        	
	        System.out.println("File " + count + " �W���ɮפ�:" + str_upload_fpath);
	        VT = new VirusTotal("c989952f44262bc7c6206732c06b7e024cad8f60e4993bdb87f1ad074cfed65d");
	        Thread.sleep(3000);
	        
	        //sendFileScan
	        Report = VT.sendFileScan(str_upload_fpath);
	        
	        for(ReportFileScan report : Report){
	            System.out.println("URL: "+report.getPermaLink()+" Response code: "+report.getResponseCode());
	            str_url=report.getPermaLink().split("/");
	            str_sha256=str_url[4];
	            System.out.println("SHA256: " + str_sha256);
	            /*detect SHA256 string position
	            for(int i=0; i<str_url.length;i++)
	            	System.out.println(str_url[i]);
	            */
	        }
        		        
	        //2. send SHA256 to scan
	        get_report_done=false;
	        do{
		        try{
			        System.out.println("���ݤ��R��...");
			        Thread.sleep(70000);
			        System.out.println("���R��...");
			        VT = new VirusTotal("c989952f44262bc7c6206732c06b7e024cad8f60e4993bdb87f1ad074cfed65d");
			        Thread.sleep(3000);
			        
			        //ReportScan
		        	Report2 = VT.ReportScan(str_sha256); //The SHA256 file
		        	get_report_done = true;
		        }
		        catch(NullPointerException e){
		        	//�|�����R����
		        	System.out.println("���R�|�������A�y�᭫��");
		        }
		        catch(Exception e2){
		        	System.out.println(e2);
		        }
	        }while( get_report_done == false );
	        
	    	//3. download scan result to excel file
	        str_output_fpath = output_dir.getPath() + "\\" + str_fname + ".xls";
	        System.out.println("�Y�N�U��...");
	        
	        dataFile = new FileWriter(str_output_fpath);
	        bw = new BufferedWriter(dataFile);
	        
	        for(ReportScan report2 : Report2){
	        	
	        	//if(report2.getDetected().equals("true")){
	        	
	        	//output log
	            //System.out.println(str_fname+"\t"+report2.getVendor()+"\t"+report2.getMalwarename()+"\t"+report2.getDetected()+"\t"+report2.getUpdate());
	            
	            //write file
	            bw.write(str_fname+"\t"+report2.getVendor()+"\t"+report2.getMalwarename()+"\t"+report2.getDetected()+"\t"+report2.getUpdate());
	            bw.newLine();
	        	//}
	            //System.out.println("AV: "+report2.getVendor()+" Detected: "+report2.getDetected()+" Update: "+report2.getUpdate()+" Malware Name: "+report2.getMalwarename());
	        }
	        //�g�J�������ɮסA���x�s
	        bw.flush();//buffer�g�Jdisk
	        dataFile.flush();
	        bw.close();
	        dataFile.close();
	        Report.clear();
	        Report2.clear();
	        
	        //�����ɮר짹����Ƨ�
	        Files.move(new File(str_upload_fpath).toPath(), new File(str_done_fpath).toPath(), REPLACE_EXISTING);
	        System.out.println("�����ɮצ�:" + str_done_fpath);
	        
	        System.out.println("�U�����R���G:"+str_output_fpath);
	        System.out.println("[" + count + "/" + input_dir_files.length + "]");
	        System.out.println();
	        //System.out.println("���ݤU�@��...");
	        //Thread.sleep(10000);
        }
        
	}

}

