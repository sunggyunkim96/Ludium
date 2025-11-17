// 환경 변수
require('dotenv').config();
const express = require('express');
const { GoogleGenAI } = require('@google/genai');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// --- Gemini API 설정 ---
const GEMINI_API_KEY = process.env.AI_API_KEY;

// .env 파일에 API 키가 없다면 서버 시작 전에 오류를 발생시키고 강제종료임으로 주의하셈!!!!
if (!GEMINI_API_KEY) {
    console.error("오류: AI_API_KEY 환경 변수가 설정되지 않았습니다.");
    process.exit(1); // 서버 시작 전에 종료됨
}

// Gemini api 관련 설정임 건들지 마세요!!
// key 값 하고 모델명 임 
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
const MODEL_NAME = 'gemini-2.5-flash';


/**
 * Gemini API를 호출하여 *프로그램 코드 묶음*을 분석
 * @param {string} programString - 분석할 파일 내용이 합쳐진 문자열
 * @returns {Promise<string>} - Gemini 모델의 분석 결과 (순수 JSON 문자열)
 */
async function analyzeProgramWithGemini(programString) {
    
    const prompt = `
   당신은 코드 분석 시스템입니다. 아래에 제공된 코드 파일을 분석하여 다음 5가지 질문에 대해 명확하게 답변하세요.
    
    1.  이 프로그램 코드에 **금융 사기(스캠) 또는 악성 코드** (데이터 탈취, 악성 URL 호출 등)가 포함되어 있습니까?
    2.  이 코드 파일이 **구문적으로 유효한(valid) 코드**입니까?
    3.  이 프로그램 코드에 **선정적인(suggestive/obscene) 문구**가 있습니까? (예: 변수명, 주석, 문자열)
    4.  이 프로그램 코드는 **유저의 민감한 정보를 수집**합니까? (예: 개인 식별 정보, 금융 정보 등)
    5.  이 프로그램 코드에 **논리적 오류** 또는 **주석/함수명과 실제 동작이 일치하지 않는 경우**가 있습니까? 

    **답변은 반드시 한글로 Markdown 코드 블록 없이 순수한 JSON 객체(raw JSON object)로만 작성해 주세요.**
    
    --- JSON 출력 형식 (필수) ---
    {
      "runId": "analysis-${new Date().toISOString().split('T')[0]}-XXXXXXXXX",
      "status": "SUCCESS" 또는 "ERROR",
      "processedAt": "${new Date().toISOString()}",
      "finalDecision": "SCAM_DETECTED" 또는 "INVALID_FORMAT" 또는 "CONTENT_WARNING" 또는 "CLEAN",
      "summary": "프로그램 전체에 대한 분석 결과를 요약합니다.",
      "reportDetails": {
        "scamCheck": {
          "detected": true 또는 false,
          "issues": ["스캠/악성 코드 관련 문제점 또는 '없음'"]
        },
        "validityCheck": {
          "valid": true 또는 false,
          "issues": ["코드 구문 유효성 관련 문제점 또는 '모든 파일이 유효함'"]
        },
        "sensationalCheck": {
          "detected": true 또는 false,
          "issues": ["선정적인 문구 관련 문제점 또는 '없음'"]
        },
        "dataCollectionCheck": {
          "detected": true 또는 false,
          "issues": ["민감 정보 수집 관련 문제점 또는 '없음'"]
        },
        "logicCheck": {
          "detected": true 또는 false,
          "issues": ["논리적 오류 또는 코드 불일치 관련 문제점 또는 '없음'"]
        }
      }
    }
    
    --- finalDecision 결정 로직 (필수) ---
    1.  'scamCheck.detected'가 true이면 "SCAM_DETECTED"
    2.  'validityCheck.valid'가 false이면 "INVALID_FORMAT"
    3.  'sensationalCheck.detected'가 true이거나 'dataCollectionCheck.detected'가 true이거나 'logicCheck.detected'가 true이면 "CONTENT_WARNING"
    4.  위 1, 2, 3에 해당하지 않고 모든 검사를 통과한 경우에만 "CLEAN"

    --- 분석할 프로그램 코드 () ---
    ${programString} 
    ---
    `;
    
    try {
        const response = await ai.models.generateContent({
            model: MODEL_NAME,
            contents: prompt,
            config: {
                responseMimeType: 'application/json',
            }
        });
        
        return response.text;
        
    } catch (error) {
        console.error("Gemini API 호출 오류:", error); // 여긴 터미널에 기록되는 메시지
        throw new Error("Gemini API 통신 중 문제가 발생했습니다."); // 여긴 클라이언트에게 전달되는 메시지
    }
}

// --- API 엔드포인트: POST /analyze ---
app.post('/analyze', async (req, res) => {
    
    //프론트엔드가 보낸 'codeFiles' 배열을 추출
    const { programMeta, codeFiles } = req.body;

    // 유효성 검사
    if (!codeFiles || !Array.isArray(codeFiles) || codeFiles.length === 0) {
        return res.status(400).json({ error: "분석할 'codeFiles' 배열이 요청 본문에 포함되어야 합니다." });
    }

    try {
        console.log(`[${new Date().toISOString()}] 요청 데이터 수신:`, req.body.programMeta);
        
        //모든 파일 내용을 하나의 문자열로 합침
        let programContext = `--- 프로그램 제목: ${programMeta.title} ---\n\n`;
        for (const file of codeFiles) {
            programContext += `--- 파일명: ${file.fileName} ---\n`;
            programContext += `${file.content}\n`; // 각 파일의 텍스트 내용
            programContext += `--- 파일 끝: ${file.fileName} ---\n\n`;
        }
        
        //합쳐진 'programContext' 문자열을 분석 함수로 전달
        const analysisResult = await analyzeProgramWithGemini(programContext);
        
        // Gemini 분석 결과가 순수 JSON 문자열일 것으로 예상하고 파싱
        let finalResponse;
        try {
            finalResponse = JSON.parse(analysisResult);
        } catch (e) {
            console.error("모델 응답 파싱 오류:", e);
            return res.status(500).json({
                status: "error",
                message: "Gemini 모델이 요청된 JSON 형식을 따르지 않았습니다.",
                detail: `모델 응답: ${analysisResult.substring(0, 100)}...`,
            });
        }
        
        // 최종적으로 파싱된 JSON 객체를 클라이언트에게 반환
        res.status(200).json({ 
            status: "success",
            analysis: finalResponse 
        });

    } catch (error) {
        console.error(`[${new Date().toISOString()}] 분석 중 서버 오류:`, error.message);// 터미널에 표기됨
        res.status(500).json({ 
            status: "error",
            message: "서버 내부에서 분석을 처리하는 중 오류가 발생했습니다.",// 사용자에게 보여질 메시지
            detail: error.message
        });
    }
});

// --- 서버 시작 --- (문구는 터미널에 표기되므로 신경 쓰지 않아도 되!!)
app.listen(port, () => {
    console.log(`JSON 분석 서버가 http://localhost:${port} 에서 실행 중입니다.`);
    console.log(`분석을 위해 POST 요청을 http://localhost:${port}/analyze 로 보내세요.`);
});